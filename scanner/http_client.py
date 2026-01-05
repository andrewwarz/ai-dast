"""HTTP Client for DAST scanner operations.

This module provides the HTTPClient class for executing HTTP requests during
security testing, capturing detailed response data for AI analysis, and handling
various HTTP operations needed for vulnerability detection.

Example:
    >>> from scanner.http_client import HTTPClient, HTTPResponse
    >>> client = HTTPClient()
    >>> response = client.send_request("https://example.com/api", method="GET")
    >>> print(response.status_code)
    200

Classes:
    HTTPClient: Main HTTP client for DAST operations.
    HTTPResponse: Dataclass encapsulating response details.
    HTTPClientError: Base exception for HTTP client errors.
    ConnectionError: Cannot connect to target.
    TimeoutError: Request timed out.
    InvalidURLError: Invalid URL provided.
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse

import httpx

from scanner.config import MAX_RESPONSE_BODY_SIZE, OLLAMA_TIMEOUT


logger = logging.getLogger(__name__)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class HTTPClientError(Exception):
    """Base exception for HTTP client errors."""
    pass


class ConnectionError(HTTPClientError):
    """Raised when unable to connect to the target."""
    pass


class TimeoutError(HTTPClientError):
    """Raised when a request times out."""
    pass


class InvalidURLError(HTTPClientError):
    """Raised when an invalid URL is provided."""
    pass


# =============================================================================
# HTTP RESPONSE DATACLASS
# =============================================================================

@dataclass
class HTTPResponse:
    """Encapsulates HTTP response details for analysis.
    
    Attributes:
        status_code: HTTP status code (e.g., 200, 404, 500).
        headers: Response headers as dictionary.
        body: Response body as string.
        elapsed_time: Request duration in seconds.
        url: Final URL (after redirects).
        method: HTTP method used.
        request_headers: Original request headers.
        request_body: Original request body (if any).
    """
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float
    url: str
    method: str
    request_headers: Dict[str, str]
    request_body: Optional[str] = None


# =============================================================================
# HTTP CLIENT
# =============================================================================

class HTTPClient:
    """HTTP client for DAST scanner operations.
    
    Provides comprehensive HTTP capabilities for security testing including
    support for all HTTP methods, custom headers, request bodies, cookie
    handling, and detailed response capture for AI analysis.
    
    Attributes:
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.
        follow_redirects: Whether to follow HTTP redirects.
        
    Example:
        >>> client = HTTPClient(timeout=30, verify_ssl=False)
        >>> response = client.send_request(
        ...     url="https://example.com/api/users",
        ...     method="POST",
        ...     headers={"Content-Type": "application/json"},
        ...     body='{"username": "test"}'
        ... )
        >>> print(f"Status: {response.status_code}")
    """
    
    DEFAULT_HEADERS: Dict[str, str] = {
        "User-Agent": "AI-DAST-Scanner/1.0 (Security Testing)",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    def __init__(
        self,
        timeout: int = OLLAMA_TIMEOUT,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        proxy: Optional[str] = None
    ) -> None:
        """Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds. Defaults to OLLAMA_TIMEOUT.
            verify_ssl: Whether to verify SSL certificates. Set False for testing.
            follow_redirects: Whether to follow HTTP redirects.
            proxy: Optional proxy URL (e.g., "http://127.0.0.1:8080").
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self._cookies: Dict[str, str] = {}

        # Create persistent HTTP client for session management
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            proxy=proxy
        )

        logger.debug(
            f"HTTPClient initialized: timeout={timeout}, "
            f"verify_ssl={verify_ssl}, follow_redirects={follow_redirects}"
        )
    
    def _validate_url(self, url: str) -> None:
        """Validate that the provided URL is well-formed.
        
        Args:
            url: URL to validate.
            
        Raises:
            InvalidURLError: If the URL is malformed or unsupported.
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise InvalidURLError(
                    f"Invalid URL '{url}': missing scheme or host"
                )
            if parsed.scheme not in ("http", "https"):
                raise InvalidURLError(
                    f"Unsupported URL scheme '{parsed.scheme}'. "
                    "Only http and https are supported."
                )
        except Exception as e:
            if isinstance(e, InvalidURLError):
                raise
            raise InvalidURLError(f"Failed to parse URL '{url}': {e}") from e

    def send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[str, Dict[str, Any]]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        follow_redirects: Optional[bool] = None,
        form_data: bool = False
    ) -> HTTPResponse:
        """Send an HTTP request and capture detailed response data.

        Args:
            url: Target URL for the request.
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
            headers: Custom request headers (merged with defaults).
            body: Request body (string, dict for JSON, or dict for form data).
            cookies: Request cookies (merged with session cookies).
            timeout: Override default timeout for this request.
            follow_redirects: Override default redirect behavior.
            form_data: If True and body is dict, send as form data instead of JSON.

        Returns:
            HTTPResponse object containing full response details.

        Raises:
            InvalidURLError: If the URL is malformed.
            ConnectionError: If unable to connect to the target.
            TimeoutError: If the request times out.
            HTTPClientError: For other HTTP-related errors.

        Example:
            >>> response = client.send_request(
            ...     url="https://example.com/api/login",
            ...     method="POST",
            ...     body={"username": "admin", "password": "test"},
            ...     form_data=True  # Send as application/x-www-form-urlencoded
            ... )
        """
        self._validate_url(url)

        # Prepare headers
        request_headers = self.DEFAULT_HEADERS.copy()
        if headers:
            request_headers.update(headers)

        # Prepare cookies
        request_cookies = self._cookies.copy()
        if cookies:
            request_cookies.update(cookies)

        # Prepare request body
        request_body_str: Optional[str] = None
        content: Optional[Union[str, bytes]] = None
        json_data: Optional[Dict[str, Any]] = None
        data: Optional[Dict[str, Any]] = None  # For form data

        if body is not None:
            if isinstance(body, dict):
                if form_data:
                    # Send as application/x-www-form-urlencoded
                    data = body
                    request_body_str = "&".join(f"{k}={v}" for k, v in body.items())
                else:
                    # Send as JSON
                    json_data = body
                    request_body_str = str(body)
            else:
                content = body
                request_body_str = body

        # Use instance defaults if not overridden
        req_timeout = timeout if timeout is not None else self.timeout
        req_follow_redirects = (
            follow_redirects if follow_redirects is not None
            else self.follow_redirects
        )

        logger.debug(
            f"Sending {method} request to {url} "
            f"(timeout={req_timeout}, follow_redirects={req_follow_redirects})"
        )

        start_time = time.time()

        try:
            # Use persistent client for proper session/cookie handling
            response = self._client.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                cookies=request_cookies,
                content=content,
                json=json_data,
                data=data,  # Form data
                timeout=req_timeout,
                follow_redirects=req_follow_redirects
            )

            elapsed_time = time.time() - start_time

            # Extract response headers as dict
            response_headers = dict(response.headers)

            # Capture response body
            response_body = response.text

            # Update session cookies from persistent client's cookie jar
            for cookie in self._client.cookies.jar:
                self._cookies[cookie.name] = cookie.value

            http_response = HTTPResponse(
                status_code=response.status_code,
                headers=response_headers,
                body=response_body,
                elapsed_time=elapsed_time,
                url=str(response.url),
                method=method.upper(),
                request_headers=request_headers,
                request_body=request_body_str
            )

            logger.info(
                f"{method.upper()} {url} -> {response.status_code} "
                f"({elapsed_time:.2f}s)"
            )

            return http_response

        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Failed to connect to {url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise TimeoutError(
                f"Request to {url} timed out after {req_timeout}s: {e}"
            ) from e
        except httpx.InvalidURL as e:
            raise InvalidURLError(f"Invalid URL {url}: {e}") from e
        except httpx.HTTPError as e:
            raise HTTPClientError(f"HTTP error for {url}: {e}") from e
        except Exception as e:
            raise HTTPClientError(
                f"Unexpected error during request to {url}: {e}"
            ) from e

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set session cookies for subsequent requests.

        Args:
            cookies: Dictionary of cookie name-value pairs.
        """
        self._cookies.update(cookies)
        logger.debug(f"Updated session cookies: {list(cookies.keys())}")

    def clear_cookies(self) -> None:
        """Clear all session cookies."""
        self._cookies.clear()
        logger.debug("Cleared all session cookies")


# =============================================================================
# RESPONSE PROCESSING UTILITIES
# =============================================================================

def truncate_body(body: str, max_size: int = MAX_RESPONSE_BODY_SIZE) -> str:
    """Truncate response body to a maximum size for AI prompts.

    Args:
        body: Response body string to truncate.
        max_size: Maximum character length. Defaults to MAX_RESPONSE_BODY_SIZE.

    Returns:
        Truncated body with indicator if truncated.

    Example:
        >>> truncated = truncate_body(large_response, max_size=4000)
    """
    if len(body) <= max_size:
        return body

    truncated = body[:max_size]
    return f"{truncated}\n\n... [TRUNCATED - {len(body) - max_size} characters omitted]"


def format_headers(headers: Dict[str, str]) -> str:
    """Format response headers as a readable string for AI prompts.

    Args:
        headers: Dictionary of header name-value pairs.

    Returns:
        Formatted string with one header per line.

    Example:
        >>> formatted = format_headers({"Content-Type": "text/html"})
        >>> print(formatted)
        Content-Type: text/html
    """
    if not headers:
        return "(No headers)"

    return "\n".join(f"{name}: {value}" for name, value in headers.items())


def extract_technology_hints(response: HTTPResponse) -> Dict[str, str]:
    """Extract technology stack indicators from response.

    Parses headers and body for technology hints like server type,
    frameworks, CMS, and programming languages.

    Args:
        response: HTTPResponse object to analyze.

    Returns:
        Dictionary of detected technology hints.

    Example:
        >>> hints = extract_technology_hints(response)
        >>> print(hints.get("server"))
        Apache/2.4.41
    """
    hints: Dict[str, str] = {}
    headers = response.headers

    # Server header
    if "server" in headers:
        hints["server"] = headers["server"]
    elif "Server" in headers:
        hints["server"] = headers["Server"]

    # X-Powered-By header
    powered_by = headers.get("x-powered-by") or headers.get("X-Powered-By")
    if powered_by:
        hints["powered_by"] = powered_by

    # ASP.NET detection
    if "x-aspnet-version" in headers or "X-AspNet-Version" in headers:
        hints["framework"] = "ASP.NET"
        version = headers.get("x-aspnet-version") or headers.get("X-AspNet-Version")
        if version:
            hints["aspnet_version"] = version

    # PHP detection from headers or body patterns
    if powered_by and "php" in powered_by.lower():
        hints["language"] = "PHP"

    # Content-Type hints
    content_type = headers.get("content-type") or headers.get("Content-Type", "")
    if content_type:
        hints["content_type"] = content_type.split(";")[0].strip()

    # Check response body for common patterns
    body_lower = response.body.lower()

    # WordPress detection
    if "wp-content" in body_lower or "wordpress" in body_lower:
        hints["cms"] = "WordPress"

    # Drupal detection
    if "drupal" in body_lower or 'name="generator" content="drupal' in body_lower:
        hints["cms"] = "Drupal"

    # Django detection
    if "csrfmiddlewaretoken" in body_lower:
        hints["framework"] = "Django"
        hints["language"] = "Python"

    # Laravel detection
    if "laravel_session" in response.body or "laravel" in body_lower:
        hints["framework"] = "Laravel"
        hints["language"] = "PHP"

    # React/Vue/Angular detection
    if "react" in body_lower or "_react" in body_lower:
        hints["frontend"] = "React"
    elif "vue" in body_lower or "__vue__" in body_lower:
        hints["frontend"] = "Vue.js"
    elif "ng-app" in body_lower or "angular" in body_lower:
        hints["frontend"] = "Angular"

    # Check Set-Cookie for framework hints
    set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie", "")
    if "phpsessid" in set_cookie.lower():
        hints["language"] = "PHP"
    elif "jsessionid" in set_cookie.lower():
        hints["language"] = "Java"
    elif "asp.net_sessionid" in set_cookie.lower():
        hints["framework"] = "ASP.NET"

    logger.debug(f"Extracted technology hints: {hints}")
    return hints


def format_response_for_analysis(
    response: HTTPResponse,
    max_body_size: int = MAX_RESPONSE_BODY_SIZE
) -> Dict[str, str]:
    """Format an HTTP response for AI analysis.

    Prepares response data in a format suitable for vulnerability analysis,
    including truncated body and formatted headers.

    Args:
        response: HTTPResponse object to format.
        max_body_size: Maximum body size for truncation.

    Returns:
        Dictionary with formatted response components.
    """
    return {
        "target_url": response.url,
        "method": response.method,
        "endpoint_path": urlparse(response.url).path or "/",
        "status_code": str(response.status_code),
        "headers": format_headers(response.headers),
        "body": truncate_body(response.body, max_body_size),
        "elapsed_time": f"{response.elapsed_time:.2f}s",
    }

