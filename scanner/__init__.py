"""AI-powered DAST Scanner using Ollama for vulnerability detection.

This package provides:
- OllamaClient: AI engine for interacting with Ollama models
- Prompt templates for security-focused vulnerability detection
- Configuration management for the scanner
- Report generation for scan results

Example:
    >>> from scanner import OllamaClient
    >>> from scanner.prompts import SYSTEM_PROMPT, format_prompt
    >>>
    >>> client = OllamaClient()
    >>> response = client.chat([
    ...     {"role": "system", "content": SYSTEM_PROMPT},
    ...     {"role": "user", "content": "Analyze this endpoint..."}
    ... ])
"""

__version__ = "0.1.0"

from scanner.ai_engine import (
    OllamaClient,
    OllamaEngineError,
    ModelNotFoundError,
    OllamaConnectionError,
    ResponseValidationError,
)
from scanner.config import configure_logging, get_config_summary
from scanner.prompts import (
    SYSTEM_PROMPT,
    VULNERABILITY_DETECTION_PROMPT,
    SELF_TERMINATION_PROMPT,
    PAYLOAD_GENERATION_PROMPT,
    format_prompt,
)
from scanner.report_generator import generate_report, save_report
from scanner.katana_client import (
    KatanaClient,
    KatanaError,
    KatanaNotInstalledError,
    KatanaExecutionError,
    KatanaTimeoutError,
)

__all__ = [
    # Version
    "__version__",
    # AI Engine
    "OllamaClient",
    "OllamaEngineError",
    "ModelNotFoundError",
    "OllamaConnectionError",
    "ResponseValidationError",
    # Configuration
    "configure_logging",
    "get_config_summary",
    # Prompts
    "SYSTEM_PROMPT",
    "VULNERABILITY_DETECTION_PROMPT",
    "SELF_TERMINATION_PROMPT",
    "PAYLOAD_GENERATION_PROMPT",
    "format_prompt",
    # Report Generation
    "generate_report",
    "save_report",
    # Katana Client
    "KatanaClient",
    "KatanaError",
    "KatanaNotInstalledError",
    "KatanaExecutionError",
    "KatanaTimeoutError",
]
