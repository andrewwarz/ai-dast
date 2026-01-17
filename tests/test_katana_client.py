"""Unit tests for Katana client integration.

This module tests the KatanaClient wrapper for endpoint discovery:
- Installation verification
- Command building and execution
- Output parsing and deduplication
- Error handling (timeout, execution errors, missing installation)
- Streaming output with progress callbacks

Run all tests: pytest tests/test_katana_client.py
Run without Katana: pytest tests/test_katana_client.py -m "not requires_katana"
Run only unit tests: pytest tests/test_katana_client.py -m "not integration"
"""

import subprocess
import shutil
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from scanner.katana_client import (
    KatanaClient,
    KatanaError,
    KatanaNotInstalledError,
    KatanaExecutionError,
    KatanaTimeoutError,
)
from scanner.config import (
    KATANA_PATH,
    KATANA_DEPTH,
    KATANA_CONCURRENCY,
    KATANA_TIMEOUT,
    KATANA_EXCLUDE_EXTENSIONS,
)


# =============================================================================
# TEST CLASS: KatanaClient Initialization
# =============================================================================


class TestKatanaClientInitialization:
    """Tests for KatanaClient initialization and configuration."""

    def test_client_initialization_default(self):
        """Test client initializes with default config values."""
        client = KatanaClient()

        assert client.katana_path == KATANA_PATH
        assert client.depth == KATANA_DEPTH
        assert client.concurrency == KATANA_CONCURRENCY
        assert client.timeout == KATANA_TIMEOUT

    def test_client_initialization_custom_path(self):
        """Test client accepts custom katana path."""
        custom_path = "/custom/path/katana"
        client = KatanaClient(katana_path=custom_path)

        assert client.katana_path == custom_path


# =============================================================================
# TEST CLASS: Installation Check
# =============================================================================


class TestKatanaInstallationCheck:
    """Tests for Katana installation verification."""

    def test_is_katana_installed_true(self):
        """Test is_katana_installed returns True when katana is found."""
        with patch.object(shutil, "which", return_value="/usr/local/bin/katana"):
            client = KatanaClient()
            assert client.is_katana_installed() is True

    def test_is_katana_installed_false(self):
        """Test is_katana_installed returns False when katana is not found."""
        with patch.object(shutil, "which", return_value=None):
            client = KatanaClient()
            assert client.is_katana_installed() is False

    def test_verify_installation_success(self):
        """Test verify_installation passes when katana is installed."""
        client = KatanaClient()
        with patch.object(client, "is_katana_installed", return_value=True):
            # Should not raise
            client.verify_installation()

    def test_verify_installation_failure(self):
        """Test verify_installation raises error when katana is not installed."""
        client = KatanaClient()
        with patch.object(client, "is_katana_installed", return_value=False):
            with pytest.raises(KatanaNotInstalledError) as exc_info:
                client.verify_installation()

            # Check error message contains installation instructions
            assert "Katana not found" in str(exc_info.value)
            assert "brew install" in str(exc_info.value) or "go install" in str(exc_info.value)


# =============================================================================
# TEST CLASS: Duration Parsing
# =============================================================================


class TestKatanaDurationParsing:
    """Tests for duration string parsing."""

    def test_parse_duration_seconds_with_suffix(self):
        """Test parsing duration with 's' suffix."""
        client = KatanaClient()
        assert client._parse_duration("5s") == 5.0
        assert client._parse_duration("300s") == 300.0

    def test_parse_duration_numeric_string(self):
        """Test parsing plain numeric string (defaults to seconds)."""
        client = KatanaClient()
        assert client._parse_duration("300") == 300.0
        assert client._parse_duration("60") == 60.0

    def test_parse_duration_integer(self):
        """Test parsing integer value."""
        client = KatanaClient()
        assert client._parse_duration(300) == 300.0

    def test_parse_duration_float(self):
        """Test parsing float value."""
        client = KatanaClient()
        assert client._parse_duration(300.5) == 300.5

    def test_parse_duration_minutes(self):
        """Test parsing duration with 'm' suffix."""
        client = KatanaClient()
        assert client._parse_duration("3m") == 180.0
        assert client._parse_duration("5m") == 300.0

    def test_parse_duration_hours(self):
        """Test parsing duration with 'h' suffix."""
        client = KatanaClient()
        assert client._parse_duration("2h") == 7200.0
        assert client._parse_duration("1h") == 3600.0

    def test_parse_duration_invalid_returns_default(self):
        """Test invalid duration strings return default 300s."""
        client = KatanaClient()
        assert client._parse_duration("invalid") == 300.0
        assert client._parse_duration("") == 300.0
        assert client._parse_duration(None) == 300.0


# =============================================================================
# TEST CLASS: Command Building
# =============================================================================


class TestKatanaCommandBuilding:
    """Tests for Katana command construction."""

    def test_build_command_basic(self):
        """Test basic command construction."""
        client = KatanaClient()
        cmd = client._build_command("http://localhost:8080")

        assert cmd[0] == client.katana_path
        assert "-u" in cmd
        assert "http://localhost:8080" in cmd
        assert "-hl" in cmd  # Headless mode
        assert "-jc" in cmd  # JavaScript crawling
        assert "-d" in cmd   # Depth flag
        assert "-c" in cmd   # Concurrency flag
        assert "-ct" in cmd  # Crawl timeout
        assert "-silent" in cmd

    def test_build_command_with_output_file(self):
        """Test command includes output file option."""
        client = KatanaClient()
        cmd = client._build_command(
            "http://example.com",
            output_file="/tmp/results.txt"
        )

        assert "-o" in cmd
        output_index = cmd.index("-o")
        assert cmd[output_index + 1] == "/tmp/results.txt"

    def test_build_command_includes_exclusions(self):
        """Test command includes file extension exclusions."""
        client = KatanaClient()
        cmd = client._build_command("http://example.com")

        assert "-ef" in cmd
        ef_index = cmd.index("-ef")
        extensions_str = cmd[ef_index + 1]

        # Check some common excluded extensions are present
        assert "png" in extensions_str
        assert "jpg" in extensions_str
        assert "css" in extensions_str


# =============================================================================
# TEST CLASS: Results Parsing
# =============================================================================


class TestKatanaResultsParsing:
    """Tests for parsing Katana output results."""

    def test_parse_results_empty(self):
        """Test parsing empty output returns empty list."""
        client = KatanaClient()
        result = client.parse_results("")
        assert result == []

    def test_parse_results_single_endpoint(self):
        """Test parsing single endpoint."""
        client = KatanaClient()
        result = client.parse_results("http://localhost:8080/api/users")
        assert result == ["http://localhost:8080/api/users"]

    def test_parse_results_multiple_endpoints(self):
        """Test parsing multiple endpoints."""
        client = KatanaClient()
        raw_output = """http://localhost:8080/
http://localhost:8080/api
http://localhost:8080/search"""

        result = client.parse_results(raw_output)

        assert len(result) == 3
        assert "http://localhost:8080/" in result
        assert "http://localhost:8080/api" in result
        assert "http://localhost:8080/search" in result

    def test_parse_results_removes_duplicates(self):
        """Test parsing removes duplicate endpoints."""
        client = KatanaClient()
        raw_output = """http://localhost:8080/api
http://localhost:8080/api
http://localhost:8080/search
http://localhost:8080/api"""

        result = client.parse_results(raw_output)

        assert len(result) == 2
        assert "http://localhost:8080/api" in result
        assert "http://localhost:8080/search" in result

    def test_parse_results_strips_whitespace(self):
        """Test parsing strips whitespace and empty lines."""
        client = KatanaClient()
        raw_output = """  http://localhost:8080/api

http://localhost:8080/search

http://localhost:8080/login"""

        result = client.parse_results(raw_output)

        assert len(result) == 3
        assert "" not in result
        # All should be stripped
        for url in result:
            assert url == url.strip()


# =============================================================================
# TEST CLASS: Output Line Parsing
# =============================================================================


class TestKatanaOutputLineParsing:
    """Tests for parsing individual Katana output lines."""

    def test_parse_output_line_valid_url(self):
        """Test parsing valid URL line."""
        client = KatanaClient()
        url, depth = client._parse_katana_output_line("http://localhost:8080/api/users")

        assert url == "http://localhost:8080/api/users"
        assert depth is not None

    def test_parse_output_line_empty(self):
        """Test parsing empty line returns None."""
        client = KatanaClient()
        url, depth = client._parse_katana_output_line("")

        assert url is None
        assert depth is None

    def test_parse_output_line_whitespace_only(self):
        """Test parsing whitespace-only line returns None."""
        client = KatanaClient()
        url, depth = client._parse_katana_output_line("   \t  ")

        assert url is None
        assert depth is None

    def test_parse_output_line_with_https(self):
        """Test parsing HTTPS URL."""
        client = KatanaClient()
        url, depth = client._parse_katana_output_line("https://example.com/secure")

        assert url == "https://example.com/secure"
        assert depth is not None

    def test_parse_output_line_calculates_depth(self):
        """Test depth calculation from URL path."""
        client = KatanaClient()

        # Root path
        url1, depth1 = client._parse_katana_output_line("http://localhost:8080/")
        assert depth1 == 0

        # Single segment
        url2, depth2 = client._parse_katana_output_line("http://localhost:8080/api")
        assert depth2 == 1

        # Multiple segments
        url3, depth3 = client._parse_katana_output_line("http://localhost:8080/api/v1/users")
        assert depth3 == 3



# =============================================================================
# TEST CLASS: Scan Execution
# =============================================================================


class TestKatanaScanExecution:
    """Tests for Katana scan execution with mocked subprocess."""

    def test_run_scan_success(self, mock_katana_subprocess):
        """Test successful scan execution."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=[
                "http://localhost:8080/",
                "http://localhost:8080/api",
                "http://localhost:8080/search",
            ]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                results = client.run_scan("http://localhost:8080")

        assert len(results) == 3
        assert "http://localhost:8080/" in results

    def test_run_scan_not_installed(self):
        """Test scan fails when Katana is not installed."""
        client = KatanaClient()

        with patch.object(
            client, "verify_installation",
            side_effect=KatanaNotInstalledError("Katana not found")
        ):
            with pytest.raises(KatanaNotInstalledError):
                client.run_scan("http://localhost:8080")

    def test_run_scan_execution_error(self, mock_katana_subprocess):
        """Test scan handles non-zero exit code."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(
            return_code=1,
            stdout_lines=[],
            stderr_lines=["Error: connection refused"]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                with pytest.raises(KatanaExecutionError) as exc_info:
                    client.run_scan("http://localhost:8080")

        assert "connection refused" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()

    def test_run_scan_timeout(self, mock_katana_subprocess):
        """Test scan handles timeout."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(wait_timeout=True)

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                with pytest.raises(KatanaTimeoutError) as exc_info:
                    client.run_scan("http://localhost:8080")

        assert "timed out" in str(exc_info.value).lower() or "timeout" in str(exc_info.value).lower()

    def test_run_scan_with_output_file(self, mock_katana_subprocess, tmp_path):
        """Test scan reads from output file when specified."""
        client = KatanaClient()
        output_file = tmp_path / "results.txt"

        # Create the output file with sample content
        output_file.write_text(
            "http://localhost:8080/\nhttp://localhost:8080/api\n"
        )

        mock_popen = mock_katana_subprocess(return_code=0, stdout_lines=[])

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                results = client.run_scan(
                    "http://localhost:8080",
                    output_file=str(output_file)
                )

        assert len(results) == 2
        assert "http://localhost:8080/" in results
        assert "http://localhost:8080/api" in results

    def test_run_scan_output_file_not_created(self, mock_katana_subprocess, tmp_path):
        """Test scan fails when output file not created."""
        client = KatanaClient()
        output_file = tmp_path / "nonexistent.txt"

        mock_popen = mock_katana_subprocess(return_code=0, stdout_lines=[])

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                with pytest.raises(KatanaExecutionError) as exc_info:
                    client.run_scan(
                        "http://localhost:8080",
                        output_file=str(output_file)
                    )

        assert "output file" in str(exc_info.value).lower() or "not created" in str(exc_info.value).lower()

    def test_run_scan_empty_results(self, mock_katana_subprocess):
        """Test scan returns empty list when no endpoints found."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(return_code=0, stdout_lines=[])

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                results = client.run_scan("http://localhost:8080")

        assert results == []


# =============================================================================
# TEST CLASS: Streaming Scan
# =============================================================================


class TestKatanaStreamingScan:
    """Tests for Katana streaming scan with progress callbacks."""

    def test_run_scan_streaming_with_callback(self, mock_katana_subprocess):
        """Test streaming scan invokes callback for each endpoint."""
        client = KatanaClient()
        callback_calls = []

        def progress_callback(count: int, url: str):
            callback_calls.append((count, url))

        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=[
                "http://localhost:8080/",
                "http://localhost:8080/api",
                "http://localhost:8080/search",
            ]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                results = client.run_scan_streaming(
                    "http://localhost:8080",
                    progress_callback=progress_callback
                )

        # Verify callback was called for each endpoint
        assert len(callback_calls) == 3
        # Verify count increments
        counts = [call[0] for call in callback_calls]
        assert counts == [1, 2, 3]
        # Verify results returned
        assert len(results) == 3

    def test_run_scan_streaming_callback_exception(self, mock_katana_subprocess):
        """Test streaming scan continues despite callback errors."""
        client = KatanaClient()
        successful_callbacks = []

        def failing_callback(count: int, url: str):
            if count == 2:
                raise ValueError("Callback error")
            successful_callbacks.append((count, url))

        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=[
                "http://localhost:8080/",
                "http://localhost:8080/api",
                "http://localhost:8080/search",
            ]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                # Should not raise despite callback error
                results = client.run_scan_streaming(
                    "http://localhost:8080",
                    progress_callback=failing_callback
                )

        # All endpoints should still be discovered
        assert len(results) == 3
        # Callback 1 and 3 should have succeeded
        assert len(successful_callbacks) == 2

    def test_run_scan_streaming_without_callback(self, mock_katana_subprocess):
        """Test streaming scan works without callback."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=[
                "http://localhost:8080/",
                "http://localhost:8080/api",
            ]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                results = client.run_scan_streaming(
                    "http://localhost:8080",
                    progress_callback=None
                )

        assert len(results) == 2


# =============================================================================
# TEST CLASS: Error Scenarios
# =============================================================================


class TestKatanaErrorScenarios:
    """Tests for various error handling scenarios."""

    def test_katana_stderr_warnings(self, mock_katana_subprocess):
        """Test scan succeeds with warnings in stderr."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=["http://localhost:8080/"],
            stderr_lines=["Warning: slow response detected"]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                # Should succeed despite stderr warnings
                results = client.run_scan("http://localhost:8080")

        assert len(results) == 1

    def test_empty_scan_results_no_error(self, mock_katana_subprocess):
        """Test empty results don't raise error."""
        client = KatanaClient()

        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=[]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                results = client.run_scan("http://localhost:8080")

        assert results == []
        # No exception should be raised

    def test_parse_results_with_only_whitespace(self):
        """Test parsing output with only whitespace lines."""
        client = KatanaClient()
        result = client.parse_results("   \n\n  \t  \n")
        assert result == []

    def test_subprocess_exception_handling(self):
        """Test handling of subprocess exceptions."""
        client = KatanaClient()

        with patch.object(client, "verify_installation"):
            with patch(
                "subprocess.Popen",
                side_effect=OSError("Failed to execute")
            ):
                with pytest.raises(KatanaExecutionError) as exc_info:
                    client.run_scan("http://localhost:8080")

        assert "Failed to execute" in str(exc_info.value) or "failed" in str(exc_info.value).lower()

    def test_katana_error_base_class(self):
        """Test all Katana errors inherit from KatanaError."""
        assert issubclass(KatanaNotInstalledError, KatanaError)
        assert issubclass(KatanaExecutionError, KatanaError)
        assert issubclass(KatanaTimeoutError, KatanaError)

    def test_invalid_output_format_handling(self, mock_katana_subprocess):
        """Test scan handles malformed/garbled output lines gracefully.

        Verifies that the client filters out invalid output lines (e.g., INFO messages,
        garbled strings, malformed URLs, binary data) and only returns valid URLs.
        """
        client = KatanaClient()

        # Mix of malformed/garbled strings and valid URLs
        mock_popen = mock_katana_subprocess(
            return_code=0,
            stdout_lines=[
                "INFO starting",           # Log message, not a URL
                "@@@",                      # Garbled string
                "http:/bad",                # Malformed URL (missing slash)
                "binary\x00data",           # Binary data
                "http://localhost:8080/valid/endpoint",  # Valid URL
                "https://example.com/api",  # Another valid URL
                "random garbage line",      # Plain text garbage
                "",                         # Empty line
                "   ",                      # Whitespace only
            ]
        )

        with patch.object(client, "verify_installation"):
            with patch("subprocess.Popen", return_value=mock_popen):
                # Should not raise any exceptions
                results = client.run_scan_streaming("http://localhost:8080")

        # Should only contain the valid URLs
        assert len(results) == 2
        assert "http://localhost:8080/valid/endpoint" in results
        assert "https://example.com/api" in results
        # Invalid lines should not be in results
        assert "INFO starting" not in results
        assert "@@@" not in results
        assert "http:/bad" not in results
        assert "binary\x00data" not in results
        assert "random garbage line" not in results


# =============================================================================
# TEST CLASS: Performance Tests
# =============================================================================


@pytest.mark.slow
class TestKatanaPerformance:
    """Performance-related tests for Katana client."""

    def test_large_result_parsing(self):
        """Test parsing large number of endpoints is efficient."""
        import time

        client = KatanaClient()

        # Generate 1000 unique endpoints
        endpoints = [
            f"http://localhost:8080/path{i}/subpath{i % 10}"
            for i in range(1000)
        ]
        raw_output = "\n".join(endpoints)

        start_time = time.time()
        results = client.parse_results(raw_output)
        elapsed = time.time() - start_time

        assert len(results) == 1000
        # Should complete in under 1 second
        assert elapsed < 1.0

    def test_parse_results_deduplication_performance(self):
        """Test deduplication performance with many duplicates."""
        import time

        client = KatanaClient()

        # Generate output with many duplicates
        base_endpoints = [
            f"http://localhost:8080/path{i}" for i in range(100)
        ]
        # Repeat each endpoint 10 times
        all_endpoints = base_endpoints * 10
        raw_output = "\n".join(all_endpoints)

        start_time = time.time()
        results = client.parse_results(raw_output)
        elapsed = time.time() - start_time

        # Should have only 100 unique endpoints
        assert len(results) == 100
        # Should complete quickly
        assert elapsed < 0.5