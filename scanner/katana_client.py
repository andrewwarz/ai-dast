"""Katana client for endpoint discovery.

This module provides a Python wrapper around the Katana CLI tool for
comprehensive endpoint discovery with headless browser support.

Example:
    >>> client = KatanaClient()
    >>> if client.is_katana_installed():
    ...     endpoints = client.run_scan("http://localhost:8080")
    ...     print(f"Found {len(endpoints)} endpoints")

    >>> # With custom output file
    >>> endpoints = client.run_scan(
    ...     "http://example.com",
    ...     output_file="/tmp/katana_results.txt"
    ... )
"""

import logging
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from scanner.config import (
    KATANA_CONCURRENCY,
    KATANA_DEPTH,
    KATANA_EXCLUDE_EXTENSIONS,
    KATANA_FILTER_REGEX,
    KATANA_PATH,
    KATANA_TIMEOUT,
)

logger = logging.getLogger(__name__)


# =============================================================================
# EXCEPTION CLASSES
# =============================================================================


class KatanaError(Exception):
    """Base exception for Katana-related errors."""

    pass


class KatanaNotInstalledError(KatanaError):
    """Raised when Katana is not installed or not found in PATH."""

    pass


class KatanaExecutionError(KatanaError):
    """Raised when Katana execution fails."""

    pass


class KatanaTimeoutError(KatanaError):
    """Raised when Katana scan times out."""

    pass


# =============================================================================
# KATANA CLIENT
# =============================================================================


class KatanaClient:
    """Client for interacting with Katana endpoint discovery tool.

    This class wraps the Katana CLI tool to provide a Python interface
    for endpoint discovery with headless browser support.

    Attributes:
        katana_path: Path to the katana executable.
        depth: Crawl depth for discovery.
        concurrency: Number of concurrent requests.
        timeout: Maximum crawl duration.
        exclude_extensions: File extensions to skip.
        filter_regex: Regex patterns to filter from results.

    Example:
        >>> client = KatanaClient()
        >>> if client.is_katana_installed():
        ...     endpoints = client.run_scan("http://localhost:8080")
        ...     print(f"Found {len(endpoints)} endpoints")
    """

    def __init__(self, katana_path: Optional[str] = None) -> None:
        """Initialize the Katana client.

        Args:
            katana_path: Optional path to katana executable.
                        Defaults to KATANA_PATH from config.
        """
        self.katana_path = katana_path or KATANA_PATH
        self.depth = KATANA_DEPTH
        self.concurrency = KATANA_CONCURRENCY
        self.timeout = KATANA_TIMEOUT
        self.exclude_extensions = KATANA_EXCLUDE_EXTENSIONS
        self.filter_regex = KATANA_FILTER_REGEX

    def _parse_duration(self, timeout_str: str) -> float:
        """Parse a duration string into seconds.

        Supports formats matching Katana's -ct flag:
        - '5s' -> 5.0 (seconds)
        - '3m' -> 180.0 (minutes)
        - '2h' -> 7200.0 (hours)
        - '300' or 300 -> 300.0 (numeric seconds)

        Args:
            timeout_str: Duration string like '3m', '5s', '2h', or numeric seconds.

        Returns:
            Duration in seconds as a float. Defaults to 300.0 on parse failure.
        """
        if timeout_str is None:
            return 300.0

        # Handle numeric types directly
        if isinstance(timeout_str, (int, float)):
            return float(timeout_str)

        timeout_str = str(timeout_str).strip().lower()
        if not timeout_str:
            return 300.0

        # Match patterns like '5s', '3m', '2h', or plain numbers
        match = re.match(r'^(\d+\.?\d*)(s|m|h)?$', timeout_str)
        if not match:
            logger.warning(
                f"Invalid timeout format '{timeout_str}', using default 300s"
            )
            return 300.0

        value = float(match.group(1))
        unit = match.group(2)

        if unit == 'm':
            return value * 60.0
        elif unit == 'h':
            return value * 3600.0
        else:  # 's' or no unit (default to seconds)
            return value

    def is_katana_installed(self) -> bool:
        """Check if Katana is installed and available in PATH.

        Returns:
            True if katana is found, False otherwise.
        """
        katana_location = shutil.which(self.katana_path)
        if katana_location:
            logger.debug(f"Katana found at: {katana_location}")
            return True
        return False

    def verify_installation(self) -> None:
        """Verify that Katana is installed and raise an error if not.

        Raises:
            KatanaNotInstalledError: If katana is not found in PATH.
        """
        if not self.is_katana_installed():
            raise KatanaNotInstalledError(
                "Katana not found. Install with:\n"
                "  macOS: brew install katana\n"
                "  Linux: go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
                "For more info: https://github.com/projectdiscovery/katana"
            )

    def _build_command(
        self, target_url: str, output_file: Optional[str] = None
    ) -> List[str]:
        """Build the katana command with all flags.

        Args:
            target_url: The URL to scan.
            output_file: Optional file path to write results to.

        Returns:
            List of command arguments for subprocess.
        """
        cmd = [
            self.katana_path,
            "-u", target_url,
            "-hl",                          # Headless mode
            "-jc",                          # JavaScript crawling
            "-d", str(self.depth),          # Crawl depth
            "-c", str(self.concurrency),    # Concurrency
            "-ct", self.timeout,            # Crawl timeout
            "-iqp",                         # Include query parameters
            "-fs", "fqdn",                  # Field scope (fully qualified domain name)
            "-fx",                          # Extract forms
            "-xhr",                         # Extract XHR requests
            "-silent",                      # Silent mode (no banner)
            "-ef", ",".join(self.exclude_extensions),  # Exclude extensions
            "-fr", self.filter_regex,       # Filter regex
        ]

        if output_file:
            cmd.extend(["-o", output_file])

        return cmd

    def run_scan(
        self, target_url: str, output_file: Optional[str] = None
    ) -> List[str]:
        """Run a Katana scan against the target URL.

        This is a convenience method that calls run_scan_streaming() without
        a progress callback for backward compatibility.

        Args:
            target_url: The URL to scan for endpoints.
            output_file: Optional file path to write raw results to.

        Returns:
            List of discovered endpoints (deduplicated and sorted).

        Raises:
            KatanaNotInstalledError: If katana is not found.
            KatanaExecutionError: If katana execution fails.
            KatanaTimeoutError: If the scan times out.
        """
        return self.run_scan_streaming(
            target_url, progress_callback=None, output_file=output_file
        )

    def parse_results(self, raw_output: str) -> List[str]:
        """Parse raw Katana output into a list of unique endpoints.

        Args:
            raw_output: Raw output string from Katana.

        Returns:
            Sorted list of unique endpoints.
        """
        if not raw_output:
            logger.debug("No Katana output to parse")
            return []

        # Split by newlines, strip whitespace, filter empty lines
        endpoints = [
            line.strip()
            for line in raw_output.split("\n")
            if line.strip()
        ]

        # Remove duplicates and sort
        unique_endpoints = sorted(set(endpoints))

        logger.info(f"Katana discovered {len(unique_endpoints)} unique endpoints")
        return unique_endpoints

    def _parse_katana_output_line(self, line: str) -> Tuple[Optional[str], Optional[int]]:
        """Parse a single line of Katana output to extract endpoint and depth.

        Args:
            line: A single line from Katana stdout.

        Returns:
            Tuple of (endpoint_url, depth_level) or (None, None) if not parseable.
        """
        line = line.strip()
        if not line:
            return None, None

        # Katana outputs URLs directly in silent mode, one per line
        # Check if line looks like a URL
        if line.startswith(('http://', 'https://')):
            # Try to extract depth from URL path depth
            try:
                from urllib.parse import urlparse
                parsed = urlparse(line)
                path_segments = [s for s in parsed.path.split('/') if s]
                depth = len(path_segments)
                return line, depth
            except Exception:
                return line, 0

        # Some Katana output formats include metadata, try to extract URL
        url_match = re.search(r'(https?://[^\s]+)', line)
        if url_match:
            url = url_match.group(1)
            return url, 0

        return None, None

    def run_scan_streaming(
        self,
        target_url: str,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        output_file: Optional[str] = None
    ) -> List[str]:
        """Run a Katana scan with streaming output for real-time progress updates.

        Args:
            target_url: The URL to scan for endpoints.
            progress_callback: Optional callback function called for each endpoint
                             discovered. Receives (endpoint_count, current_url).
            output_file: Optional file path to write raw results to.

        Returns:
            List of discovered endpoints (deduplicated and sorted).

        Raises:
            KatanaNotInstalledError: If katana is not found.
            KatanaExecutionError: If katana execution fails.
            KatanaTimeoutError: If the scan times out.
        """
        self.verify_installation()

        cmd = self._build_command(target_url, output_file)
        logger.debug(f"Running Katana command (streaming): {' '.join(cmd)}")

        # Parse timeout from config (e.g., '3m' -> 180.0 seconds)
        timeout_seconds = self._parse_duration(self.timeout)
        logger.debug(f"Katana timeout: {self.timeout} -> {timeout_seconds}s")

        discovered_endpoints: List[str] = []
        discovered_set: set = set()
        output_lines: List[str] = []
        stderr_output: List[str] = []
        exception_holder: List[Exception] = []

        def read_stdout(process: subprocess.Popen) -> None:
            """Thread function to read stdout line-by-line."""
            try:
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        output_lines.append(line)
                        endpoint, depth = self._parse_katana_output_line(line)
                        if endpoint and endpoint not in discovered_set:
                            discovered_set.add(endpoint)
                            discovered_endpoints.append(endpoint)
                            if progress_callback:
                                try:
                                    progress_callback(len(discovered_endpoints), endpoint)
                                except Exception as cb_err:
                                    logger.debug(f"Progress callback error: {cb_err}")
            except Exception as e:
                exception_holder.append(e)

        def read_stderr(process: subprocess.Popen) -> None:
            """Thread function to read stderr."""
            try:
                for line in iter(process.stderr.readline, ''):
                    if not line:
                        break
                    stderr_output.append(line.strip())
            except Exception:
                pass

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )

            # Start reader threads
            stdout_thread = threading.Thread(target=read_stdout, args=(process,))
            stderr_thread = threading.Thread(target=read_stderr, args=(process,))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            # Wait for process with timeout
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise KatanaTimeoutError(
                    f"Katana scan timed out after {timeout_seconds:.0f}s. "
                    f"Consider reducing depth or increasing timeout."
                )

            # Wait for threads to finish reading
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)

            # Check for exceptions in reader threads
            if exception_holder:
                logger.warning(f"Stdout reader exception: {exception_holder[0]}")

            # Check return code
            if return_code != 0:
                error_msg = '\n'.join(stderr_output) if stderr_output else "Unknown error"
                raise KatanaExecutionError(f"Katana scan failed: {error_msg}")

            # If output file was specified, read from it for final results
            if output_file:
                output_path = Path(output_file)
                if output_path.exists():
                    raw_output = output_path.read_text()
                    return self.parse_results(raw_output)
                else:
                    raise KatanaExecutionError(
                        f"Katana completed but output file was not created: {output_file}. "
                        f"Check file path permissions."
                    )

            # Return deduplicated and sorted results from streaming
            return sorted(discovered_set)

        except (KatanaTimeoutError, KatanaExecutionError):
            raise
        except Exception as e:
            raise KatanaExecutionError(f"Katana scan failed: {e}") from e

