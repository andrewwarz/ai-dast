"""Unit tests for the Scanner and HTTP Client modules.

This module tests:
- HTTPClient: request handling, response parsing, error handling
- DASTScanner: orchestration, payload generation, vulnerability detection
"""

from unittest.mock import MagicMock, patch, PropertyMock
from urllib.parse import urlparse

import pytest

from scanner.http_client import (
    HTTPClient,
    HTTPResponse,
    HTTPClientError,
    ConnectionError,
    TimeoutError,
    InvalidURLError,
    truncate_body,
    format_headers,
    extract_technology_hints,
    format_response_for_analysis,
)
from scanner.scanner import DASTScanner, Vulnerability, TestResult


# =============================================================================
# HTTP CLIENT TESTS
# =============================================================================

class TestHTTPClient:
    """Tests for HTTPClient functionality."""

    def test_http_client_initialization(self):
        """Test client setup with various configurations."""
        # Default configuration
        client = HTTPClient()
        assert client.timeout > 0
        assert client.verify_ssl is True
        assert client.follow_redirects is True

        # Custom configuration
        client = HTTPClient(
            timeout=60,
            verify_ssl=False,
            follow_redirects=False,
            proxy="http://localhost:8080"
        )
        assert client.timeout == 60
        assert client.verify_ssl is False
        assert client.follow_redirects is False
        assert client.proxy == "http://localhost:8080"

    def test_validate_url(self):
        """Test URL validation logic."""
        client = HTTPClient()

        # Valid URLs should not raise
        client._validate_url("http://example.com")
        client._validate_url("https://example.com/path")
        client._validate_url("http://localhost:8080/api/v1")

        # Invalid URLs should raise InvalidURLError
        with pytest.raises(InvalidURLError):
            client._validate_url("not-a-url")

        with pytest.raises(InvalidURLError):
            client._validate_url("ftp://example.com")

        with pytest.raises(InvalidURLError):
            client._validate_url("")

    @patch("scanner.http_client.httpx.Client")
    def test_send_request_success(self, mock_httpx_client):
        """Test successful GET request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.url = "http://example.com/test"
        mock_response.cookies = {}

        mock_client_instance = MagicMock()
        mock_client_instance.request.return_value = mock_response
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_httpx_client.return_value = mock_client_instance

        client = HTTPClient()
        response = client.send_request("http://example.com/test")

        assert response.status_code == 200
        assert response.body == "<html><body>Test</body></html>"
        assert response.method == "GET"

    @patch("scanner.http_client.httpx.Client")
    def test_send_request_post_with_body(self, mock_httpx_client):
        """Test POST request with JSON and form data."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = '{"id": 1, "status": "created"}'
        mock_response.url = "http://example.com/api/users"
        mock_response.cookies = {}

        mock_client_instance = MagicMock()
        mock_client_instance.request.return_value = mock_response
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_httpx_client.return_value = mock_client_instance

        client = HTTPClient()

        # Test with dict body (JSON)
        response = client.send_request(
            "http://example.com/api/users",
            method="POST",
            body={"username": "test", "email": "test@example.com"}
        )
        assert response.status_code == 201
        assert response.method == "POST"

    @patch("scanner.http_client.httpx.Client")
    def test_send_request_custom_headers(self, mock_httpx_client):
        """Test custom header injection."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.url = "http://example.com/api"
        mock_response.cookies = {}

        mock_client_instance = MagicMock()
        mock_client_instance.request.return_value = mock_response
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_httpx_client.return_value = mock_client_instance

        client = HTTPClient()
        response = client.send_request(
            "http://example.com/api",
            headers={"Authorization": "Bearer token123", "X-Custom": "value"}
        )

        # Verify custom headers were passed
        call_kwargs = mock_client_instance.request.call_args[1]
        assert "Authorization" in call_kwargs["headers"]
        assert call_kwargs["headers"]["Authorization"] == "Bearer token123"

    @patch("scanner.http_client.httpx.Client")
    def test_send_request_cookies(self, mock_httpx_client):
        """Test cookie handling and session persistence."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.url = "http://example.com"
        mock_response.cookies = {"session_id": "abc123"}

        mock_client_instance = MagicMock()
        mock_client_instance.request.return_value = mock_response
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_httpx_client.return_value = mock_client_instance

        client = HTTPClient()
        client.set_cookies({"existing_cookie": "value"})

        response = client.send_request("http://example.com")

        # Session should now have both cookies
        assert "session_id" in client._cookies or "existing_cookie" in client._cookies

    @patch("scanner.http_client.httpx.Client")
    def test_send_request_connection_error(self, mock_httpx_client):
        """Test ConnectionError exception handling."""
        import httpx

        mock_client_instance = MagicMock()
        mock_client_instance.request.side_effect = httpx.ConnectError("Connection refused")
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_httpx_client.return_value = mock_client_instance

        client = HTTPClient()

        with pytest.raises(ConnectionError) as exc_info:
            client.send_request("http://localhost:9999")

        assert "Failed to connect" in str(exc_info.value)

    @patch("scanner.http_client.httpx.Client")
    def test_send_request_timeout_error(self, mock_httpx_client):
        """Test TimeoutError exception handling."""
        import httpx

        mock_client_instance = MagicMock()
        mock_client_instance.request.side_effect = httpx.TimeoutException("Request timed out")
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_httpx_client.return_value = mock_client_instance

        client = HTTPClient()

        with pytest.raises(TimeoutError) as exc_info:
            client.send_request("http://example.com/slow")

        assert "timed out" in str(exc_info.value)

    def test_send_request_invalid_url(self):
        """Test InvalidURLError for malformed URLs."""
        client = HTTPClient()

        with pytest.raises(InvalidURLError):
            client.send_request("not-a-valid-url")


# =============================================================================
# RESPONSE PROCESSING UTILITY TESTS
# =============================================================================

class TestResponseProcessingUtilities:
    """Tests for response processing utility functions."""

    def test_truncate_body(self):
        """Test body truncation utility."""
        short_body = "Short body"
        assert truncate_body(short_body, max_size=100) == short_body

        long_body = "x" * 5000
        truncated = truncate_body(long_body, max_size=1000)
        assert len(truncated) < len(long_body)
        assert "[TRUNCATED" in truncated

    def test_format_headers(self):
        """Test header formatting."""
        headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41",
        }
        formatted = format_headers(headers)
        assert "Content-Type: text/html" in formatted
        assert "Server: Apache/2.4.41" in formatted

        # Empty headers
        assert format_headers({}) == "(No headers)"

    def test_extract_technology_hints(self, sample_http_response):
        """Test technology detection from headers/body."""
        hints = extract_technology_hints(sample_http_response)

        assert hints.get("server") == "Apache/2.4.41"
        assert hints.get("powered_by") == "PHP/7.4.3"
        assert hints.get("content_type") == "text/html"

    def test_extract_technology_hints_wordpress(self, mock_http_response):
        """Test WordPress detection."""
        response = mock_http_response(
            body='<html><link rel="stylesheet" href="/wp-content/themes/test/style.css"></html>'
        )
        hints = extract_technology_hints(response)
        assert hints.get("cms") == "WordPress"

    def test_extract_technology_hints_django(self, mock_http_response):
        """Test Django detection."""
        response = mock_http_response(
            body='<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
        )
        hints = extract_technology_hints(response)
        assert hints.get("framework") == "Django"
        assert hints.get("language") == "Python"

    def test_format_response_for_analysis(self, sample_http_response):
        """Test response formatting for AI prompts."""
        formatted = format_response_for_analysis(sample_http_response)

        assert "target_url" in formatted
        assert "method" in formatted
        assert "status_code" in formatted
        assert "headers" in formatted
        assert "body" in formatted
        assert formatted["method"] == "GET"
        assert formatted["status_code"] == "200"


# =============================================================================
# DAST SCANNER TESTS
# =============================================================================

class TestDASTScanner:
    """Tests for DASTScanner orchestration."""

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_scanner_initialization(self, mock_http_client, mock_ollama_client):
        """Test scanner setup and client initialization."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")

        assert scanner.target_url == "http://localhost:8080"
        assert scanner.vulnerabilities == []
        assert scanner.request_count == 0
        mock_ollama_client.assert_called_once()
        mock_http_client.assert_called_once()

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_construct_test_url(self, mock_http_client, mock_ollama_client):
        """Test URL construction with payloads."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")

        # Test with root endpoint
        url = scanner._construct_test_url("' OR '1'='1", "/")
        assert "test=" in url
        assert "' OR '1'='1" in url

        # Test with different endpoint
        url = scanner._construct_test_url("<script>alert(1)</script>", "/api/search")
        assert "/api/search" in url
        assert "test=" in url

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_extract_endpoints(self, mock_http_client, mock_ollama_client):
        """Test endpoint extraction from HTML/JSON."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")

        # Create mock response with links
        from tests.conftest import create_mock_response
        response = create_mock_response(
            body='''
            <html>
            <a href="/page1">Page 1</a>
            <a href="/page2">Page 2</a>
            <form action="/submit" method="post"></form>
            <a href="http://localhost:8080/internal">Internal</a>
            <a href="http://external.com/other">External</a>
            </html>
            ''',
            url="http://localhost:8080/"
        )

        endpoints = scanner._extract_endpoints(response)

        assert "/page1" in endpoints
        assert "/page2" in endpoints
        assert "/submit" in endpoints
        assert "/internal" in endpoints
        # External links should not be included
        assert "/other" not in endpoints

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_parse_payloads(self, mock_http_client, mock_ollama_client):
        """Test payload parsing from AI responses."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")

        ai_response = """
        **Payload**: `' OR '1'='1`
        **Purpose**: SQL injection bypass
        **Expected Response**: Login success

        **Payload**: `1 UNION SELECT NULL,username,password FROM users--`
        **Purpose**: Data extraction
        **Expected Response**: User data in response
        """

        payloads = scanner._parse_payloads(ai_response)

        assert len(payloads) == 2
        assert payloads[0]["payload"] == "' OR '1'='1"
        assert "SQL injection" in payloads[0]["purpose"]

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_check_for_vulnerability(self, mock_http_client, mock_ollama_client):
        """Test vulnerability detection from AI analysis."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")

        # Analysis indicating vulnerability
        vuln_analysis = "Vulnerability found: SQL Injection with HIGH CONFIDENCE"
        assert scanner._check_for_vulnerability(vuln_analysis) is True

        # Analysis indicating no vulnerability
        clean_analysis = "The application appears secure. No vulnerabilities detected."
        assert scanner._check_for_vulnerability(clean_analysis) is False

        # Analysis with severity indicator
        severity_analysis = "Severity: Critical - Command Injection exploitable"
        assert scanner._check_for_vulnerability(severity_analysis) is True

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_parse_termination_decision(self, mock_http_client, mock_ollama_client):
        """Test STOP/CONTINUE decision parsing."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")

        # Test STOP decision
        stop_response = "Based on analysis...\nSTOP\nTesting complete."
        assert scanner._parse_termination_decision(stop_response) == "stop"

        # Test CONTINUE decision
        continue_response = "More testing needed...\nCONTINUE\nProceed with next category."
        assert scanner._parse_termination_decision(continue_response) == "continue"

        # Test no explicit decision (defaults to continue)
        ambiguous_response = "The scan is progressing normally."
        assert scanner._parse_termination_decision(ambiguous_response) == "continue"

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_get_scan_results(self, mock_http_client, mock_ollama_client):
        """Test results compilation."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ai.get_model_info.return_value = {
            "model": "llama3:latest",
            "host": "http://localhost:11434",
            "timeout": 120
        }
        mock_ollama_client.return_value = mock_ai

        scanner = DASTScanner("http://localhost:8080")
        scanner.start_time = 1000.0
        scanner.request_count = 50

        with patch("scanner.scanner.time.time", return_value=1045.5):
            results = scanner.get_scan_results()

        assert results["target_url"] == "http://localhost:8080"
        assert "statistics" in results
        assert results["statistics"]["total_requests"] == 50
        assert results["statistics"]["status"] == "completed"
        assert "model_info" in results

    @patch("scanner.scanner.OllamaClient")
    @patch("scanner.scanner.HTTPClient")
    def test_scan_with_max_requests_limit(self, mock_http_client, mock_ollama_client):
        """Test request limit enforcement."""
        mock_ai = MagicMock()
        mock_ai.model = "llama3:latest"
        mock_ai.get_model_info.return_value = {"model": "llama3:latest"}
        mock_ai.chat_with_retry.return_value = "No vulnerabilities found."
        mock_ai.chat.return_value = "CONTINUE"
        mock_ollama_client.return_value = mock_ai

        mock_http = MagicMock()
        from tests.conftest import create_mock_response
        mock_http.send_request.return_value = create_mock_response()
        mock_http_client.return_value = mock_http

        scanner = DASTScanner("http://localhost:8080", max_requests=5)
        results = scanner.scan()

        # Should stop due to request limit
        assert results["statistics"]["total_requests"] <= 5
