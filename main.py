#!/usr/bin/env python3
"""AI DAST Scanner - Command Line Interface.

AI-powered Dynamic Application Security Testing scanner that uses LLMs
for intelligent vulnerability detection and analysis.

Supported LLM Providers:
    - ollama: Local Ollama instance (default)
    - openrouter: OpenRouter API (access to multiple models)
    - openai: OpenAI API (GPT models)

Usage:
    python main.py --target http://localhost:8080
    python main.py --target http://example.com --model qwen3
    python main.py --target http://example.com --provider openai --model gpt-4o
    python main.py --target http://example.com --model openrouter/anthropic/claude-3.5-sonnet
    python main.py --target http://example.com --output ./reports --verbose
"""

import argparse
import sys
import time
from urllib.parse import urlparse

from scanner.ai_engine import (
    OllamaClient,
    OllamaConnectionError,
    OllamaEngineError,
    ModelNotFoundError,
)
from scanner.config import (
    configure_logging,
    PREFERRED_MODELS,
    VALID_PROVIDERS,
    LLM_PROVIDER,
    get_effective_provider_and_model,
)
from scanner.http_client import (
    HTTPClientError,
    ConnectionError as HTTPConnectionError,
    TimeoutError as HTTPTimeoutError,
    InvalidURLError,
)
from scanner.report_generator import generate_report, save_report, SEVERITY_ICONS
from scanner.scanner import DASTScanner, ScanProgress, ScanPhase


# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "1.0.0"

# Default model for security testing (provider-specific defaults apply)
# Users can override via --model flag or environment variables
DEFAULT_RECOMMENDED_MODEL = "qwen3"  # Strong reasoning for security analysis (for Ollama)

BANNER = """
╔═══════════════════════════════════════════════════════════════════╗
║          ╔═╗╦  ╔╦╗╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗               ║
║          ╠═╣║   ║║╠═╣╚═╗ ║   ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝               ║
║          ╩ ╩╩  ═╩╝╩ ╩╚═╝ ╩   ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═               ║
║                                                                   ║
║          AI-Powered Dynamic Application Security Testing         ║
╚═══════════════════════════════════════════════════════════════════╝
"""


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ai-dast",
        description="AI-powered Dynamic Application Security Testing scanner",
        epilog=(
            "Examples:\n"
            "  python main.py --target http://localhost:8080\n"
            "  python main.py --target http://example.com --model qwen3\n"
            "  python main.py --target http://example.com --provider openai --model gpt-4o\n"
            "  python main.py --target http://example.com --model openrouter/anthropic/claude-3.5-sonnet\n"
            "  python main.py --target https://api.example.com --no-verify-ssl --verbose\n"
            "\n"
            f"Supported providers: {', '.join(sorted(VALID_PROVIDERS))}\n"
            f"Preferred Ollama models: {', '.join(PREFERRED_MODELS[:5])}\n"
            "\n"
            "Model names can be prefixed with provider (e.g., ollama/llama3, openai/gpt-4o)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="URL",
        help="Target URL to scan (e.g., http://localhost:8080)"
    )

    # LLM Provider selection
    parser.add_argument(
        "--provider", "-p",
        metavar="NAME",
        choices=sorted(VALID_PROVIDERS),
        default=None,
        help=(
            f"LLM provider to use (choices: {', '.join(sorted(VALID_PROVIDERS))}). "
            f"Default: from LLM_PROVIDER env var or 'ollama'. "
            "Can also be specified via model prefix (e.g., openai/gpt-4o)."
        )
    )

    # Model selection (supports provider-prefixed names)
    parser.add_argument(
        "--model", "-m",
        metavar="NAME",
        default=None,
        help=(
            "LLM model to use. Can include provider prefix (e.g., ollama/llama3, "
            "openai/gpt-4o, openrouter/anthropic/claude-3.5-sonnet). "
            f"Default for Ollama: auto-select from available models. "
            "For OpenAI: gpt-4o. For OpenRouter: requires OPENROUTER_MODEL env var."
        )
    )

    # Output options
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="reports",
        help="Output directory for reports (default: reports/)"
    )
    parser.add_argument(
        "--filename",
        metavar="NAME",
        default=None,
        help="Custom report filename (default: auto-generated timestamp)"
    )

    # HTTP options
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--verify-ssl",
        action="store_true",
        dest="verify_ssl",
        default=True,
        help="Verify SSL certificates (default)"
    )
    ssl_group.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL certificate verification (for testing)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        metavar="SEC",
        default=30,
        help="HTTP request timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        metavar="N",
        default=None,
        help="Maximum requests to send (default: unlimited)"
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="HTTP proxy URL (e.g., http://127.0.0.1:8080)"
    )

    # Logging options
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    log_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output (WARNING level only)"
    )

    # Version
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    return parser


def validate_url(url: str) -> bool:
    """Validate that the URL is well-formed HTTP/HTTPS URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

def print_banner() -> None:
    """Display the application banner."""
    print(BANNER)


def print_scan_info(target: str, provider: str, model: str, verify_ssl: bool) -> None:
    """Display scan configuration before starting.

    Args:
        target: Target URL being scanned.
        provider: LLM provider name (e.g., ollama, openai, openrouter).
        model: Full model name (may include provider prefix).
        verify_ssl: Whether SSL verification is enabled.
    """
    ssl_status = "✓ Enabled" if verify_ssl else "✗ Disabled"
    print(f"{'━' * 67}")
    print(f"  Target:     {target}")
    print(f"  Provider:   {provider}")
    print(f"  Model:      {model}")
    print(f"  SSL Verify: {ssl_status}")
    print(f"{'━' * 67}")
    print()


def print_progress(message: str, emoji: str = "🔍") -> None:
    """Print a progress message with timestamp."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {emoji} {message}")


# Track last progress line for overwriting
_last_progress_len = 0


def print_scan_progress(progress: ScanProgress, quiet: bool = False) -> None:
    """Print real-time scan progress with overwriting previous line.

    Args:
        progress: ScanProgress object with current state.
        quiet: If True, don't print anything.
    """
    global _last_progress_len

    if quiet:
        return

    # Format the progress line
    timestamp = time.strftime("%H:%M:%S")
    status_line = progress.format_status_line()
    line = f"\r[{timestamp}] {status_line}"

    # Pad with spaces to overwrite previous line
    padding = max(0, _last_progress_len - len(line))
    print(f"{line}{' ' * padding}", end="", flush=True)
    _last_progress_len = len(line)

    # Print newline on phase changes for permanent log
    if progress.phase in (ScanPhase.DISCOVERY, ScanPhase.ANALYSIS,
                          ScanPhase.ATTACK, ScanPhase.EXPLOITATION):
        if progress.phase_progress == 0 or progress.phase_progress >= 99:
            print()  # Newline to preserve this progress line
            _last_progress_len = 0


def create_progress_callback(quiet: bool = False):
    """Create a progress callback function for the scanner.

    Args:
        quiet: If True, callback does nothing.

    Returns:
        Callback function that accepts ScanProgress.
    """
    def callback(progress: ScanProgress) -> None:
        print_scan_progress(progress, quiet=quiet)
    return callback


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins}m {secs}s"


def print_summary(scan_results: dict, report_path: str) -> None:
    """Display scan summary with vulnerability counts."""
    stats = scan_results.get("statistics", {})
    vulns = scan_results.get("vulnerabilities", [])
    model_info = scan_results.get("model_info", {})

    duration = stats.get("duration_seconds", 0)
    total_requests = stats.get("total_requests", 0)
    endpoints = stats.get("unique_endpoints_tested", 0)

    # Attack vector stats
    attack_vectors_identified = stats.get("attack_vectors_identified", 0)
    attack_vectors_tested = stats.get("attack_vectors_tested", 0)
    attack_vectors_vulnerable = stats.get("attack_vectors_vulnerable", 0)
    forms_discovered = stats.get("forms_discovered", 0)

    # Count by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for vuln in vulns:
        severity = vuln.get("severity", "Informational")
        if severity in severity_counts:
            severity_counts[severity] += 1

    print()
    print(f"{'═' * 67}")
    print("  SCAN COMPLETE")
    print(f"{'═' * 67}")
    print()

    # Statistics
    model_name = model_info.get('model', 'N/A')
    # Extract provider from model name if available
    if '/' in str(model_name):
        provider_display = model_name.split('/')[0]
    else:
        provider_display = model_info.get('provider', 'ollama')

    print("  📊 Scan Statistics")
    print(f"     • Duration:       {format_duration(duration)}")
    print(f"     • Requests:       {total_requests}")
    print(f"     • Endpoints:      {endpoints}")
    print(f"     • Forms Found:    {forms_discovered}")
    print(f"     • Provider:       {provider_display}")
    print(f"     • Model:          {model_name}")
    print()

    # Attack vector summary
    print("  🎯 Attack Vector Analysis")
    print(f"     • Vectors Identified:  {attack_vectors_identified}")
    print(f"     • Vectors Tested:      {attack_vectors_tested}")
    print(f"     • Vectors Vulnerable:  {attack_vectors_vulnerable}")
    print()

    # Vulnerability summary
    total_vulns = len(vulns)
    print(f"  🔐 Vulnerabilities Found: {total_vulns}")
    if total_vulns > 0:
        for severity, count in severity_counts.items():
            if count > 0:
                icon = SEVERITY_ICONS.get(severity, "⚪")
                print(f"     {icon} {severity}: {count}")

        # Show top 3 critical/high findings preview
        critical_high = [v for v in vulns if v.get("severity") in ("Critical", "High")]
        if critical_high:
            print()
            print("  ⚠️  Top Findings Preview:")
            for vuln in critical_high[:3]:
                icon = SEVERITY_ICONS.get(vuln.get("severity"), "⚪")
                print(f"     {icon} {vuln.get('type')}: {vuln.get('url', 'N/A')[:50]}")
            if len(critical_high) > 3:
                print(f"     ... and {len(critical_high) - 3} more critical/high findings")
    else:
        print("     ✅ No vulnerabilities detected")

    print()
    print(f"  📄 Report saved to:")
    print(f"     {report_path}")
    print()
    print(f"{'═' * 67}")


def print_error(message: str, tip: str = None) -> None:
    """Print an error message with optional tip."""
    print(f"\n❌ Error: {message}", file=sys.stderr)
    if tip:
        print(f"💡 Tip: {tip}", file=sys.stderr)
    print()


# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main() -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    # Parse arguments
    parser = create_argument_parser()
    args = parser.parse_args()

    # Configure logging based on flags
    if args.verbose:
        log_level = "DEBUG"
    elif args.quiet:
        log_level = "WARNING"
    else:
        log_level = "INFO"

    configure_logging(level=log_level)

    # Validate target URL
    if not validate_url(args.target):
        print_error(
            f"Invalid target URL: {args.target}",
            "Provide a valid HTTP/HTTPS URL (e.g., http://localhost:8080)"
        )
        return 4

    # Display banner (unless quiet mode)
    if not args.quiet:
        print_banner()

    # Determine effective provider and model
    # Priority: 1. Model prefix (e.g., openai/gpt-4o), 2. --provider flag, 3. LLM_PROVIDER env
    model_arg = args.model
    if args.provider and model_arg and "/" not in model_arg:
        # Prepend provider prefix to model if --provider is specified and model has no prefix
        model_arg = f"{args.provider}/{model_arg}"
    elif args.provider and not model_arg:
        # Provider specified but no model - we need to get the provider-specific default model
        # and format it with the provider prefix
        _, default_model = get_effective_provider_and_model(None)
        if default_model:
            model_arg = f"{args.provider}/{default_model}"
        else:
            # No default model, just use provider prefix (client will select best model)
            model_arg = f"{args.provider}/"

    # Get effective provider for display and error messages
    # If args.provider was explicitly set, use that; otherwise extract from model_arg
    if args.provider:
        effective_provider = args.provider
    else:
        effective_provider, _ = get_effective_provider_and_model(model_arg)

    # Initialize scanner with progress callback
    if not args.quiet:
        print_progress("Initializing scanner...", "🚀")

    # Create progress callback for real-time updates
    progress_callback = create_progress_callback(quiet=args.quiet)

    try:
        scanner = DASTScanner(
            target_url=args.target,
            verify_ssl=args.verify_ssl,
            timeout=args.timeout,
            max_requests=args.max_requests,
            proxy=args.proxy,
            model=model_arg,
            provider=args.provider,
            progress_callback=progress_callback,
        )

    except OllamaConnectionError as e:
        # Provide provider-agnostic error message
        if effective_provider == "ollama":
            print_error(
                "Cannot connect to Ollama",
                "Start Ollama with: ollama serve"
            )
        elif effective_provider == "openai":
            print_error(
                "Cannot connect to OpenAI API",
                "Check your OPENAI_API_KEY environment variable"
            )
        elif effective_provider == "openrouter":
            print_error(
                "Cannot connect to OpenRouter API",
                "Check your OPENROUTER_API_KEY environment variable"
            )
        else:
            print_error(
                f"Cannot connect to LLM provider '{effective_provider}'",
                "Check your API configuration and credentials"
            )
        return 2
    except ModelNotFoundError as e:
        # Provide provider-specific model help
        if effective_provider == "ollama":
            print_error(
                "No Ollama models available",
                "Pull a model first: ollama pull qwen3"
            )
        elif effective_provider == "openai":
            print_error(
                "Model not available",
                "Try using --model gpt-4o or gpt-4-turbo"
            )
        elif effective_provider == "openrouter":
            print_error(
                "Model not specified for OpenRouter",
                "Set OPENROUTER_MODEL env var or use --model openrouter/anthropic/claude-3.5-sonnet"
            )
        else:
            print_error(
                f"No models available for provider '{effective_provider}'",
                "Specify a model with --model flag"
            )
        return 5
    except OllamaEngineError as e:
        print_error(f"LLM engine error: {e}")
        return 2
    except InvalidURLError as e:
        print_error(
            f"Invalid target URL format: {args.target}",
            "Provide a valid HTTP/HTTPS URL"
        )
        return 4
    except HTTPClientError as e:
        print_error(f"HTTP client error: {e}")
        return 3

    # Display scan configuration with provider info
    model_name = scanner._ai_client.model
    # Extract provider from model name if it has a prefix
    if "/" in model_name:
        display_provider = model_name.split("/")[0]
    else:
        display_provider = effective_provider
    if not args.quiet:
        print_scan_info(args.target, display_provider, model_name, args.verify_ssl)

    # Execute scan
    if not args.quiet:
        print()
        print_progress("Starting scan phases: Discovery → Analysis → Attack", "🚀")
        print()

    try:
        scan_results = scanner.scan()
        # Ensure we're on a new line after progress updates
        print()
    except HTTPConnectionError as e:
        print_error(
            f"Cannot connect to target: {args.target}",
            "Verify the URL is accessible"
        )
        return 3
    except HTTPTimeoutError as e:
        print_error(
            f"Connection to target timed out",
            "Try increasing --timeout value"
        )
        return 3
    except OllamaEngineError as e:
        print_error(f"AI analysis failed: {e}")
        return 2
    except Exception as e:
        print_error(f"Scan failed: {e}")
        return 1

    # Check if scan completed with an error
    scan_error = scan_results.get("error")
    scan_status = scan_results.get("statistics", {}).get("status")
    if scan_error or scan_status != "completed":
        print_error(f"Scan failed: {scan_error or 'Unknown error'}")
        return 1

    if not args.quiet:
        print_progress("Scan completed, generating report...", "📊")

    # Generate report
    try:
        report_content = generate_report(scan_results)
    except ValueError as e:
        print_error(f"Failed to generate report: {e}")
        return 6

    # Save report
    try:
        report_path = save_report(
            report_content,
            output_dir=args.output,
            filename=args.filename,
        )
    except OSError as e:
        print_error(
            f"Failed to save report to {args.output}",
            "Check directory permissions"
        )
        return 6

    # Display summary
    if not args.quiet:
        print_summary(scan_results, report_path)
    else:
        # Even in quiet mode, show the report path
        print(f"Report saved: {report_path}")

    return 0


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
