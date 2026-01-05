"""Pytest configuration and shared fixtures.

This module provides shared fixtures for testing the AI DAST Scanner components:
- Mock fixtures for Ollama client and HTTP responses
- Sample data fixtures for scan results and vulnerabilities
- Integration test fixtures for target application connectivity
"""

import socket
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import httpx
import pytest

from scanner.http_client import HTTPResponse


# =============================================================================
# TEST MARKERS CONFIGURATION
# =============================================================================

def pytest_configure(config):
    """Register custom markers for test categorization."""
    config.addinivalue_line(
        "markers", "integration: mark test as requiring external services (vulnerable app, Ollama)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "requires_target: mark test as requiring the vulnerable application to be running"
    )
    config.addinivalue_line(
        "markers", "requires_ollama: mark test as requiring Ollama to be running"
    )


# =============================================================================
# URL FIXTURES
# =============================================================================

@pytest.fixture
def sample_url():
    """Provide a sample URL for testing."""
    return "http://localhost:8080"


@pytest.fixture
def target_url():
    """Provide target application URL and skip test if not accessible.

    Returns:
        str: Target application base URL if accessible.

    Raises:
        pytest.skip: If target application is not accessible.
    """
    target_url = "http://localhost:8080"
    if not _is_service_available("localhost", 8080):
        pytest.skip("Vulnerable application is not running on localhost:8080")
    return target_url


def _is_service_available(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a service is available at the given host and port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# =============================================================================
# LITELLM MOCK FIXTURES
# =============================================================================

def create_mock_litellm_response(content: str, reasoning_content: str = None):
    """Helper to create a mock LiteLLM ModelResponse."""
    mock_message = MagicMock()
    mock_message.content = content
    mock_message.reasoning_content = reasoning_content

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    return mock_response


@pytest.fixture
def mock_litellm_response():
    """Return sample chat response simulating LiteLLM's completion() response."""
    return create_mock_litellm_response("This is a test response from the AI model.")


@pytest.fixture
def mock_litellm_response_with_reasoning():
    """Return chat response with reasoning field."""
    return create_mock_litellm_response(
        content="The final answer is 42.",
        reasoning_content="Let me think about this step by step..."
    )


@pytest.fixture
def mock_litellm_completion(mock_litellm_response):
    """Return a MagicMock configured to simulate LiteLLM completion behavior.

    This fixture creates a mock that can be used to test code that depends
    on LiteLLMClient without requiring a running LLM service.
    """
    with patch("scanner.ai_engine.litellm.completion") as mock_completion:
        mock_completion.return_value = mock_litellm_response
        yield mock_completion


# Backward compatibility aliases for old fixture names
@pytest.fixture
def mock_ollama_list_response():
    """Deprecated: Use mock_litellm_response instead."""
    mock_model_1 = MagicMock()
    mock_model_1.model = "llama3:latest"
    mock_model_2 = MagicMock()
    mock_model_2.model = "mistral:latest"
    mock_model_3 = MagicMock()
    mock_model_3.model = "codellama:latest"

    mock_response = MagicMock()
    mock_response.models = [mock_model_1, mock_model_2, mock_model_3]
    return mock_response


@pytest.fixture
def mock_ollama_chat_response():
    """Deprecated: Use mock_litellm_response instead."""
    return create_mock_litellm_response("This is a test response from the AI model.")


@pytest.fixture
def mock_ollama_chat_response_with_thinking():
    """Deprecated: Use mock_litellm_response_with_reasoning instead."""
    return create_mock_litellm_response(
        content="The final answer is 42.",
        reasoning_content="Let me think about this step by step..."
    )


@pytest.fixture
def mock_ollama_client(mock_litellm_response):
    """Deprecated: Use mock_litellm_completion instead."""
    with patch("scanner.ai_engine.litellm.completion") as mock_completion:
        mock_completion.return_value = mock_litellm_response
        yield mock_completion


# =============================================================================
# HTTP RESPONSE FIXTURES
# =============================================================================

def create_mock_response(
    status_code: int = 200,
    body: str = "<html><body>Test</body></html>",
    headers: Optional[Dict[str, str]] = None,
    url: str = "http://localhost:8080/test",
    method: str = "GET",
    elapsed_time: float = 0.1,
    request_headers: Optional[Dict[str, str]] = None,
    request_body: Optional[str] = None
) -> HTTPResponse:
    """Create a mock HTTPResponse for testing.

    Args:
        status_code: HTTP status code.
        body: Response body string.
        headers: Response headers dict.
        url: Request URL.
        method: HTTP method.
        elapsed_time: Request duration in seconds.
        request_headers: Original request headers.
        request_body: Original request body.

    Returns:
        HTTPResponse object with the specified attributes.
    """
    if headers is None:
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "Apache/2.4.41",
        }
    if request_headers is None:
        request_headers = {
            "User-Agent": "AI-DAST-Scanner/1.0",
            "Accept": "*/*",
        }

    return HTTPResponse(
        status_code=status_code,
        headers=headers,
        body=body,
        elapsed_time=elapsed_time,
        url=url,
        method=method,
        request_headers=request_headers,
        request_body=request_body
    )


@pytest.fixture
def mock_http_response():
    """Factory fixture for creating HTTPResponse objects."""
    return create_mock_response


@pytest.fixture
def sample_http_response():
    """Provide a sample HTTP response for testing."""
    return create_mock_response(
        status_code=200,
        body='<html><head><title>Test Page</title></head><body><h1>Welcome</h1></body></html>',
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
        },
        url="http://localhost:8080/",
    )


@pytest.fixture
def sample_vulnerable_response():
    """Provide a sample response indicating SQL injection vulnerability."""
    return create_mock_response(
        status_code=200,
        body='''
        {
            "error": "You have an error in your SQL syntax; check the manual that
            corresponds to your MySQL server version for the right syntax to use
            near '1' OR '1'='1' at line 1"
        }
        ''',
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Server": "Python/3.11 aiohttp/3.9",
        },
        url="http://localhost:8080/api/users?id=1' OR '1'='1",
    )


# =============================================================================
# VULNERABILITY AND SCAN RESULT FIXTURES
# =============================================================================

@pytest.fixture
def sample_vulnerabilities() -> List[Dict[str, Any]]:
    """Provide sample vulnerabilities with various severity levels."""
    return [
        {
            "type": "SQL Injection",
            "severity": "Critical",
            "confidence": "High",
            "evidence": "SQL syntax error in response",
            "url": "http://localhost:8080/api/users?id=1",
            "method": "GET",
            "payload": "1' OR '1'='1",
            "exploitation_steps": "Inject SQL payload in id parameter",
            "recommendation": "Use parameterized queries",
        },
        {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "confidence": "High",
            "evidence": "<script>alert('XSS')</script> reflected in response",
            "url": "http://localhost:8080/search?q=test",
            "method": "GET",
            "payload": "<script>alert('XSS')</script>",
            "exploitation_steps": "Inject script tag in q parameter",
            "recommendation": "Implement output encoding",
        },
        {
            "type": "Information Disclosure",
            "severity": "Medium",
            "confidence": "Medium",
            "evidence": "Server version exposed in headers",
            "url": "http://localhost:8080/",
            "method": "GET",
            "payload": None,
            "exploitation_steps": None,
            "recommendation": "Remove version information from server headers",
        },
        {
            "type": "Security Misconfiguration",
            "severity": "Low",
            "confidence": "Low",
            "evidence": "Missing security headers",
            "url": "http://localhost:8080/",
            "method": "GET",
            "payload": None,
            "exploitation_steps": None,
            "recommendation": "Add X-Frame-Options and CSP headers",
        },
    ]


@pytest.fixture
def sample_scan_results(sample_vulnerabilities) -> Dict[str, Any]:
    """Provide complete scan results dictionary for report testing."""
    return {
        "target_url": "http://localhost:8080",
        "vulnerabilities": sample_vulnerabilities,
        "statistics": {
            "total_requests": 150,
            "unique_endpoints_tested": 12,
            "vulnerabilities_found": len(sample_vulnerabilities),
            "duration_seconds": 45.5,
            "scan_start": "2024-01-15T14:30:22",
            "status": "completed",
        },
        "model_info": {
            "model": "llama3:latest",
            "host": "http://localhost:11434",
            "timeout": 120,
        },
        "tested_vectors": {
            "SQL Injection": ["' OR '1'='1", "1; DROP TABLE users--", "UNION SELECT"],
            "Cross-Site Scripting (XSS)": ["<script>alert(1)</script>", "<img onerror=alert(1)>"],
            "Command Injection": ["; ls -la", "| cat /etc/passwd"],
        },
        "technology_hints": {
            "server": "Apache/2.4.41",
            "language": "PHP",
            "powered_by": "PHP/7.4.3",
        },
    }


@pytest.fixture
def empty_scan_results() -> Dict[str, Any]:
    """Provide scan results with no vulnerabilities found."""
    return {
        "target_url": "http://localhost:8080",
        "vulnerabilities": [],
        "statistics": {
            "total_requests": 50,
            "unique_endpoints_tested": 5,
            "vulnerabilities_found": 0,
            "duration_seconds": 15.2,
            "scan_start": "2024-01-15T14:30:22",
            "status": "completed",
        },
        "model_info": {
            "model": "llama3:latest",
            "host": "http://localhost:11434",
            "timeout": 120,
        },
        "tested_vectors": {},
        "technology_hints": {},
    }


# =============================================================================
# AI RESPONSE FIXTURES
# =============================================================================

@pytest.fixture
def sample_vulnerability_analysis():
    """Provide sample AI analysis indicating vulnerability found."""
    return """
## Vulnerability Analysis

**Vulnerability Found:** Yes
**Type:** SQL Injection
**Severity:** Critical
**Confidence:** High

### Evidence
The response contains a MySQL error message indicating SQL syntax error,
which suggests the input is being directly concatenated into SQL queries.

### Exploitation Steps
1. Inject `' OR '1'='1` to bypass authentication
2. Use UNION-based injection to extract data

### Recommended Fix
Use parameterized queries or prepared statements instead of string concatenation.
"""


@pytest.fixture
def sample_clean_analysis():
    """Provide sample AI analysis indicating no vulnerability."""
    return """
## Vulnerability Analysis

**Vulnerability Found:** No

The response appears to be properly sanitized. No indicators of
SQL injection, XSS, or other common vulnerabilities were detected.

The application correctly handles the test payload without exposing
sensitive information or error messages.
"""


@pytest.fixture
def sample_payload_generation_response():
    """Provide sample AI response for payload generation."""
    return """
## SQL Injection Payloads

**Payload**: `' OR '1'='1`
**Purpose**: Basic SQL injection to bypass authentication
**Expected Response**: Login success or database error

**Payload**: `1 UNION SELECT NULL,username,password FROM users--`
**Purpose**: UNION-based data extraction
**Expected Response**: User credentials in response

**Payload**: `1; DROP TABLE users--`
**Purpose**: Destructive SQL injection test
**Expected Response**: Database error or unusual behavior
"""


@pytest.fixture
def sample_termination_continue_response():
    """Provide sample AI response for continuing testing."""
    return """
Based on the scan progress analysis:

- Only 30% of vulnerability categories have been tested
- Recent requests are still finding new endpoints
- No diminishing returns observed yet

CONTINUE

Testing should continue to ensure comprehensive coverage.
"""


@pytest.fixture
def sample_termination_stop_response():
    """Provide sample AI response for stopping testing."""
    return """
Based on the scan progress analysis:

- All major vulnerability categories have been tested
- Last 20 requests found no new vulnerabilities
- Sufficient coverage achieved for the target scope

STOP

Testing can be safely concluded. Recommend generating the final report.
"""
