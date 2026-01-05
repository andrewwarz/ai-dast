"""DAST Scanner Orchestration Module.

This module provides the DASTScanner class that orchestrates AI-powered
vulnerability detection workflows. It combines HTTP operations with AI analysis
to perform intelligent security testing with self-termination capabilities.

Example:
    >>> from scanner.scanner import DASTScanner
    >>> scanner = DASTScanner("https://example.com")
    >>> results = scanner.scan()
    >>> for vuln in results["vulnerabilities"]:
    ...     print(f"{vuln['type']}: {vuln['severity']}")

Classes:
    DASTScanner: Main orchestration class for DAST scanning.
    ScanResult: Dataclass containing scan results.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from scanner.ai_engine import OllamaClient, OllamaEngineError
from scanner.config import (
    MAX_RESPONSE_BODY_SIZE,
    SELF_TERMINATION_WINDOW,
    get_effective_provider_and_model,
)
from scanner.http_client import (
    HTTPClient,
    HTTPClientError,
    HTTPResponse,
    format_headers,
    format_response_for_analysis,
    truncate_body,
    extract_technology_hints,
)
from scanner.prompts import (
    SYSTEM_PROMPT,
    VULNERABILITY_DETECTION_PROMPT,
    SELF_TERMINATION_PROMPT,
    PAYLOAD_GENERATION_PROMPT,
    SQLI_EXPLOITATION_PROMPT,
    CREDENTIAL_LOGIN_PROMPT,
    format_prompt,
)


logger = logging.getLogger(__name__)


# =============================================================================
# VULNERABILITY CATEGORIES
# =============================================================================

VULNERABILITY_CATEGORIES: List[str] = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Path Traversal",
    "Server-Side Template Injection (SSTI)",
    "Authentication Bypass",
    "Broken Access Control",
    "Information Disclosure",
    "Security Misconfiguration",
    "XML External Entity (XXE)",
]


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability.
    
    Attributes:
        type: Vulnerability category (e.g., "SQL Injection").
        severity: Severity level (Critical/High/Medium/Low/Informational).
        confidence: Detection confidence (High/Medium/Low).
        evidence: Response data showing the vulnerability.
        url: Affected endpoint URL.
        method: HTTP method used.
        payload: Test payload that triggered it (if applicable).
        exploitation_steps: How to exploit the vulnerability.
        recommendation: Mitigation advice.
    """
    type: str
    severity: str
    confidence: str
    evidence: str
    url: str
    method: str
    payload: Optional[str] = None
    exploitation_steps: Optional[str] = None
    recommendation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format."""
        return {
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "url": self.url,
            "method": self.method,
            "payload": self.payload,
            "exploitation_steps": self.exploitation_steps,
            "recommendation": self.recommendation,
        }


@dataclass
class TestResult:
    """Represents a single test execution result.

    Attributes:
        url: Tested URL.
        method: HTTP method used.
        payload: Payload sent (if any).
        vulnerability_type: Type of vulnerability tested.
        response: HTTP response received.
        finding: Whether a vulnerability was found.
        analysis: AI analysis result.
    """
    url: str
    method: str
    payload: Optional[str]
    vulnerability_type: str
    response: HTTPResponse
    finding: bool
    analysis: str


@dataclass
class FormData:
    """Represents an HTML form discovered during scanning.

    Attributes:
        action: Form action URL (where form submits to).
        method: HTTP method (GET/POST).
        inputs: Dictionary of input field names to their default values.
        endpoint: The endpoint where the form was found.
    """
    action: str
    method: str
    inputs: Dict[str, str]
    endpoint: str


# =============================================================================
# DAST SCANNER
# =============================================================================

class DASTScanner:
    """AI-powered Dynamic Application Security Testing scanner.

    Orchestrates the complete DAST workflow including reconnaissance,
    vulnerability testing, and intelligent self-termination. Uses AI
    to generate test payloads, analyze responses, and detect vulnerabilities.

    Attributes:
        target_url: Base URL being tested.
        vulnerabilities: List of discovered vulnerabilities.
        request_count: Total requests sent during the scan.

    Example:
        >>> scanner = DASTScanner("https://example.com")
        >>> results = scanner.scan()
        >>> print(f"Found {len(results['vulnerabilities'])} vulnerabilities")

        >>> # With custom configuration
        >>> scanner = DASTScanner(
        ...     target_url="https://api.example.com",
        ...     verify_ssl=False,
        ...     max_requests=100
        ... )
    """

    # Termination check interval (every N requests)
    TERMINATION_CHECK_INTERVAL: int = 20

    def __init__(
        self,
        target_url: str,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_requests: Optional[int] = None,
        proxy: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> None:
        """Initialize the DAST scanner.

        Args:
            target_url: Base URL of the target application.
            verify_ssl: Whether to verify SSL certificates.
            timeout: HTTP request timeout in seconds.
            max_requests: Maximum requests to send (None for unlimited).
            proxy: Optional proxy URL for HTTP requests.
            model: Optional model name, can include provider prefix (e.g., "openai/gpt-4o").
            provider: Optional LLM provider override (e.g., "ollama", "openai", "openrouter").
                     If set and model has no prefix, the provider will be prepended.

        Raises:
            OllamaEngineError: If the LLM provider is not available.
        """
        self.target_url = target_url.rstrip("/")
        self.max_requests = max_requests

        # Resolve effective model with provider prefix
        # Priority: model prefix > provider arg > env default
        effective_model = model
        if provider and model and "/" not in model:
            # Provider explicitly set, model has no prefix - prepend provider
            effective_model = f"{provider}/{model}"
        elif provider and not model:
            # Provider set but no model - get default model for provider
            effective_provider, default_model = get_effective_provider_and_model(None)
            if default_model:
                effective_model = f"{provider}/{default_model}"
            else:
                # Let the client auto-select with provider prefix
                effective_model = f"{provider}/"
        elif not model:
            # No model or provider specified - use environment configuration
            effective_provider, default_model = get_effective_provider_and_model(None)
            if default_model:
                effective_model = f"{effective_provider}/{default_model}"

        # Initialize AI client with resolved model
        self._ai_client = OllamaClient(model=effective_model)
        self._http_client = HTTPClient(
            timeout=timeout,
            verify_ssl=verify_ssl,
            follow_redirects=True,
            proxy=proxy
        )

        # State tracking
        self.vulnerabilities: List[Vulnerability] = []
        self.tested_endpoints: Set[str] = set()
        self.pending_endpoints: Set[str] = set()  # Endpoints discovered but not yet tested
        self.tested_vectors: Dict[str, List[str]] = {}
        self.request_count: int = 0
        self.start_time: Optional[float] = None
        self.test_results: List[TestResult] = []
        # Track confirmed vulnerable endpoints per category to avoid redundant testing
        # Key: (vuln_category, endpoint_or_form_action), Value: True if confirmed vulnerable
        self._confirmed_vulns: Set[tuple] = set()
        self.conversation_history: List[Dict[str, str]] = []
        self.detected_technology: Dict[str, str] = {}
        self.discovered_forms: List[FormData] = []  # Forms found during scanning
        self.discovered_params: Dict[str, List[str]] = {}  # URL params per endpoint

        # Exploitation state
        self.extracted_credentials: List[Dict[str, str]] = []  # Credentials from SQLi
        self.authenticated: bool = False  # Whether we've logged in
        self.auth_user: Optional[str] = None  # Username we logged in as
        self.exploitation_results: List[Dict[str, Any]] = []  # Data extracted via exploitation

        # Initialize conversation with system prompt
        self.conversation_history.append({
            "role": "system",
            "content": SYSTEM_PROMPT
        })

        logger.info(
            f"DASTScanner initialized for {self.target_url} "
            f"using model {self._ai_client.model}"
        )

    def scan(self) -> Dict[str, Any]:
        """Execute the complete DAST scanning workflow.

        Performs reconnaissance, vulnerability testing, and returns
        comprehensive scan results.

        Returns:
            Dictionary containing:
                - vulnerabilities: List of discovered vulnerabilities
                - statistics: Scan statistics (requests, duration, etc.)
                - model_info: AI model information
                - tested_vectors: Attack types tested
                - target_url: Scanned URL
                - technology_hints: Detected technology stack

        Example:
            >>> results = scanner.scan()
            >>> for vuln in results["vulnerabilities"]:
            ...     print(f"[{vuln['severity']}] {vuln['type']}")
        """
        self.start_time = time.time()
        logger.info(f"Starting DAST scan of {self.target_url}")

        try:
            # Phase 1: Initial Reconnaissance
            logger.info("Phase 1: Performing reconnaissance...")
            self._perform_reconnaissance()

            # Phase 2: Vulnerability Testing Loop
            logger.info("Phase 2: Starting vulnerability testing...")
            self._vulnerability_testing_loop()

            # Phase 3: Exploitation (if SQLi found)
            sqli_vulns = [v for v in self.vulnerabilities if "sql" in v.type.lower()]
            if sqli_vulns:
                logger.info("Phase 3: Exploiting SQL Injection vulnerabilities...")
                self._exploitation_phase(sqli_vulns)

            # Compile results
            return self.get_scan_results()

        except Exception as e:
            logger.error(f"Scan error: {e}")
            # Return partial results on error
            return self.get_scan_results(error=str(e))

    def get_scan_results(self, error: Optional[str] = None) -> Dict[str, Any]:
        """Compile and return comprehensive scan results.

        Args:
            error: Optional error message if scan was interrupted.

        Returns:
            Dictionary with complete scan results and statistics.
        """
        elapsed_time = 0.0
        if self.start_time:
            elapsed_time = time.time() - self.start_time

        results = {
            "target_url": self.target_url,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "statistics": {
                "total_requests": self.request_count,
                "unique_endpoints_tested": len(self.tested_endpoints),
                "vulnerabilities_found": len(self.vulnerabilities),
                "duration_seconds": round(elapsed_time, 2),
                "scan_start": datetime.fromtimestamp(
                    self.start_time
                ).isoformat() if self.start_time else None,
            },
            "model_info": self._ai_client.get_model_info(),
            "tested_vectors": self.tested_vectors,
            "technology_hints": self.detected_technology,
        }

        if error:
            results["error"] = error
            results["statistics"]["status"] = "error"
        else:
            results["statistics"]["status"] = "completed"

        logger.info(
            f"Scan completed: {len(self.vulnerabilities)} vulnerabilities found "
            f"in {elapsed_time:.1f}s ({self.request_count} requests)"
        )

        return results

    def _perform_reconnaissance(self) -> None:
        """Perform initial reconnaissance on the target.

        Sends initial request to gather technology hints and
        identify potential entry points for testing.
        """
        try:
            # Send initial GET request to target
            response = self._http_client.send_request(
                url=self.target_url,
                method="GET"
            )
            self.request_count += 1
            self.tested_endpoints.add("/")

            # Extract technology hints
            self.detected_technology = extract_technology_hints(response)

            # Analyze initial response for vulnerabilities and entry points
            analysis = self._analyze_response(
                response,
                context="Initial reconnaissance of target application"
            )

            # Log technology detection
            if self.detected_technology:
                tech_summary = ", ".join(
                    f"{k}={v}" for k, v in self.detected_technology.items()
                )
                logger.info(f"Detected technology: {tech_summary}")

            # Extract forms (critical for testing login pages, search forms, etc.)
            forms = self._extract_forms(response, "/")
            self.discovered_forms.extend(forms)
            if forms:
                logger.info(f"Found {len(forms)} forms with input fields")
                for form in forms:
                    field_names = list(form.inputs.keys())
                    logger.debug(
                        f"  Form: {form.method} {form.action} "
                        f"fields={field_names}"
                    )

            # Extract additional endpoints from response and queue for testing
            endpoints = self._extract_endpoints(response)
            for endpoint in endpoints:
                if endpoint not in self.tested_endpoints:
                    self.pending_endpoints.add(endpoint)
            logger.info(
                f"Reconnaissance complete. "
                f"Found {len(endpoints)} potential endpoints, "
                f"{len(self.discovered_forms)} forms, "
                f"{len(self.pending_endpoints)} queued for testing."
            )

        except HTTPClientError as e:
            logger.error(f"Reconnaissance failed: {e}")
            raise

    def _vulnerability_testing_loop(self) -> None:
        """Execute the main vulnerability testing loop.

        Iterates through vulnerability categories and discovered forms/endpoints,
        generates payloads, executes tests, and analyzes responses for
        vulnerabilities. Prioritizes form-based testing for injection attacks.
        """
        for vuln_category in VULNERABILITY_CATEGORIES:
            # Check request limit
            if self.max_requests and self.request_count >= self.max_requests:
                logger.info(f"Request limit ({self.max_requests}) reached")
                break

            # Check self-termination conditions periodically
            if (self.request_count > 0 and
                self.request_count % self.TERMINATION_CHECK_INTERVAL == 0):
                if not self._should_continue_testing():
                    logger.info("Self-termination triggered")
                    break

            logger.info(f"Testing for: {vuln_category}")

            try:
                # Generate payloads for this vulnerability type
                payloads = self._generate_payloads(vuln_category)

                if not payloads:
                    logger.warning(
                        f"No payloads generated for {vuln_category}"
                    )
                    continue

                # Track that we're testing this category
                if vuln_category not in self.tested_vectors:
                    self.tested_vectors[vuln_category] = []

                # PRIORITY 1: Test discovered forms (login forms, search, etc.)
                # This is where injection vulnerabilities are most likely
                for form in self.discovered_forms:
                    if self.max_requests and self.request_count >= self.max_requests:
                        break

                    # Skip forms already confirmed vulnerable for this category
                    form_key = (vuln_category, form.action)
                    if form_key in self._confirmed_vulns:
                        logger.debug(
                            f"Skipping {form.action} for {vuln_category} - already confirmed vulnerable"
                        )
                        continue

                    for payload_info in payloads:
                        if self.max_requests and self.request_count >= self.max_requests:
                            break

                        # Check again inside payload loop in case we just confirmed it
                        if form_key in self._confirmed_vulns:
                            break

                        self._execute_form_test(vuln_category, payload_info, form)

                # PRIORITY 2: Test URL parameters on discovered endpoints
                endpoints_to_test = list(self.pending_endpoints)
                for endpoint in endpoints_to_test:
                    if self.max_requests and self.request_count >= self.max_requests:
                        break

                    # Skip endpoints already confirmed vulnerable for this category
                    endpoint_key = (vuln_category, endpoint)
                    if endpoint_key in self._confirmed_vulns:
                        logger.debug(
                            f"Skipping {endpoint} for {vuln_category} - already confirmed vulnerable"
                        )
                        continue

                    for payload_info in payloads:
                        if self.max_requests and self.request_count >= self.max_requests:
                            break

                        # Check again inside payload loop in case we just confirmed it
                        if endpoint_key in self._confirmed_vulns:
                            break

                        self._execute_url_param_test(vuln_category, payload_info, endpoint)

            except OllamaEngineError as e:
                logger.error(f"AI error testing {vuln_category}: {e}")
                continue
            except HTTPClientError as e:
                logger.error(f"HTTP error testing {vuln_category}: {e}")
                continue

    def _execute_form_test(
        self,
        vuln_category: str,
        payload_info: Dict[str, str],
        form: FormData
    ) -> None:
        """Execute a payload test against a form with proper POST/GET and field injection.

        This is the primary testing method for injection vulnerabilities.
        It injects payloads into form input fields and submits using the
        correct HTTP method.

        Args:
            vuln_category: Category of vulnerability being tested.
            payload_info: Payload details including the payload string.
            form: FormData object containing form action, method, and fields.
        """
        payload = payload_info.get("payload", "")

        # Build the form submission URL
        form_url = urljoin(self.target_url, form.action)

        # Identify injectable fields (text, password, search, textarea - not hidden/submit)
        injectable_fields = []
        for field_name, default_value in form.inputs.items():
            # Skip fields that are likely CSRF tokens or submit buttons
            lower_name = field_name.lower()
            if any(skip in lower_name for skip in ['csrf', 'token', 'submit', 'button']):
                continue
            injectable_fields.append(field_name)

        if not injectable_fields:
            logger.debug(f"No injectable fields in form {form.action}")
            return

        # Test injection in each injectable field
        for target_field in injectable_fields:
            if self.max_requests and self.request_count >= self.max_requests:
                break

            # Build form data with payload in target field
            form_data = {}
            for field_name, default_value in form.inputs.items():
                if field_name == target_field:
                    form_data[field_name] = payload
                else:
                    form_data[field_name] = default_value or "test"

            try:
                # Send request using form's method
                if form.method == "POST":
                    response = self._http_client.send_request(
                        url=form_url,
                        method="POST",
                        body=form_data,
                        form_data=True  # Send as application/x-www-form-urlencoded
                    )
                else:
                    # GET form - append as query parameters
                    params = "&".join(f"{k}={v}" for k, v in form_data.items())
                    get_url = f"{form_url}?{params}" if "?" not in form_url else f"{form_url}&{params}"
                    response = self._http_client.send_request(
                        url=get_url,
                        method="GET"
                    )

                self.request_count += 1

                # Track tested
                self.tested_endpoints.add(form.action)
                self.tested_vectors[vuln_category].append(f"{target_field}={payload[:30]}")

                # Analyze response
                context = (
                    f"Testing {vuln_category} on form field '{target_field}' "
                    f"at {form.action} with payload: {payload[:100]}"
                )
                analysis = self._analyze_response(response, context=context)

                # Record result
                finding = self._check_for_vulnerability(analysis)
                test_result = TestResult(
                    url=form_url,
                    method=form.method,
                    payload=f"{target_field}={payload}",
                    vulnerability_type=vuln_category,
                    response=response,
                    finding=finding,
                    analysis=analysis
                )
                self.test_results.append(test_result)

                if finding:
                    self._parse_and_record_vulnerability(
                        analysis=analysis,
                        vuln_type=vuln_category,
                        url=form_url,
                        method=form.method,
                        payload=f"{target_field}={payload}",
                        response=response
                    )
                    # Mark this form as confirmed vulnerable for this category
                    # to skip further payloads and move on
                    self._confirmed_vulns.add((vuln_category, form.action))
                    logger.info(
                        f"Confirmed {vuln_category} on {form.action}, moving to next target"
                    )
                    return  # Exit early - no need to test more payloads on this form

            except HTTPClientError as e:
                logger.debug(f"Form test failed: {e}")

    def _execute_url_param_test(
        self,
        vuln_category: str,
        payload_info: Dict[str, str],
        endpoint: str = "/"
    ) -> None:
        """Execute a payload test via URL query parameter.

        Fallback testing method for endpoints without forms.

        Args:
            vuln_category: Category of vulnerability being tested.
            payload_info: Payload details including the payload string.
            endpoint: The endpoint path to test.
        """
        payload = payload_info.get("payload", "")

        # Construct test URL with payload
        test_url = self._construct_test_url(payload, endpoint)

        try:
            response = self._http_client.send_request(
                url=test_url,
                method="GET"
            )
            self.request_count += 1

            # Track tested endpoint
            self.tested_endpoints.add(endpoint)
            self.pending_endpoints.discard(endpoint)
            self.tested_vectors[vuln_category].append(payload[:50])

            # Analyze response
            analysis = self._analyze_response(
                response,
                context=f"Testing for {vuln_category} at {endpoint} with payload: {payload[:100]}"
            )

            # Record result
            finding = self._check_for_vulnerability(analysis)
            test_result = TestResult(
                url=test_url,
                method="GET",
                payload=payload,
                vulnerability_type=vuln_category,
                response=response,
                finding=finding,
                analysis=analysis
            )
            self.test_results.append(test_result)

            if finding:
                self._parse_and_record_vulnerability(
                    analysis=analysis,
                    vuln_type=vuln_category,
                    url=test_url,
                    method="GET",
                    payload=payload,
                    response=response
                )
                # Mark this endpoint as confirmed vulnerable for this category
                # to skip further payloads and move on
                self._confirmed_vulns.add((vuln_category, endpoint))
                logger.info(
                    f"Confirmed {vuln_category} on {endpoint}, moving to next target"
                )
                return  # Exit early - no need to test more payloads on this endpoint

        except HTTPClientError as e:
            logger.debug(f"URL param test failed: {e}")

    def _analyze_response(
        self,
        response: HTTPResponse,
        context: str = ""
    ) -> str:
        """Analyze an HTTP response for vulnerabilities using AI.

        Args:
            response: HTTPResponse object to analyze.
            context: Additional context for the analysis.

        Returns:
            AI analysis result as string.
        """
        # Format response for prompt
        formatted = format_response_for_analysis(response)

        # Build the prompt
        prompt = format_prompt(
            VULNERABILITY_DETECTION_PROMPT,
            target_url=formatted["target_url"],
            method=formatted["method"],
            endpoint_path=formatted["endpoint_path"],
            status_code=formatted["status_code"],
            headers=formatted["headers"],
            body=formatted["body"]
        )

        # Add context if provided
        if context:
            prompt = f"Context: {context}\n\n{prompt}"

        # Add to conversation and get response
        self.conversation_history.append({
            "role": "user",
            "content": prompt
        })

        try:
            analysis = self._ai_client.chat_with_retry(
                self.conversation_history
            )

            # Add response to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": analysis
            })

            # Limit conversation history to prevent token overflow
            self._trim_conversation_history()

            return analysis

        except OllamaEngineError as e:
            logger.error(f"AI analysis failed: {e}")
            return f"Analysis error: {e}"

    def _generate_payloads(self, vulnerability_type: str) -> List[Dict[str, str]]:
        """Generate test payloads for a vulnerability type using AI.

        Args:
            vulnerability_type: Type of vulnerability to generate payloads for.

        Returns:
            List of payload dictionaries with payload, purpose, expected_response.
        """
        # Build the prompt
        prompt = format_prompt(
            PAYLOAD_GENERATION_PROMPT,
            target_url=self.target_url,
            parameter_name="id",  # Default parameter
            current_value="1",
            detected_technology=self._format_technology_hints(),
            content_type=self.detected_technology.get("content_type", "text/html"),
            vulnerability_type=vulnerability_type
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            response = self._ai_client.chat_with_retry(messages)
            return self._parse_payloads(response)

        except OllamaEngineError as e:
            logger.error(f"Payload generation failed: {e}")
            return []

    def _should_continue_testing(self) -> bool:
        """Evaluate whether testing should continue using AI.

        Uses self-termination evaluation to determine if testing
        has achieved sufficient coverage.

        Returns:
            True if testing should continue, False otherwise.
        """
        elapsed_time = time.time() - self.start_time if self.start_time else 0

        # Calculate recent findings
        recent_window = min(
            SELF_TERMINATION_WINDOW,
            len(self.test_results)
        )
        recent_findings = sum(
            1 for r in self.test_results[-recent_window:] if r.finding
        )

        # Format tested vectors
        tested_vectors_str = "\n".join(
            f"- {cat}: {len(payloads)} payloads tested"
            for cat, payloads in self.tested_vectors.items()
        )

        # Format recent results summary
        recent_results_str = self._format_recent_results()

        # Build the prompt
        prompt = format_prompt(
            SELF_TERMINATION_PROMPT,
            total_requests=str(self.request_count),
            unique_endpoints=str(len(self.tested_endpoints)),
            vulnerabilities_found=str(len(self.vulnerabilities)),
            recent_window=str(recent_window),
            recent_findings=str(recent_findings),
            time_elapsed=f"{elapsed_time:.0f}s",
            tested_vectors=tested_vectors_str or "None yet",
            recent_results=recent_results_str or "No results yet"
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            response = self._ai_client.chat(messages)

            # Parse explicit decision token from response
            # Look for a line that starts with STOP or CONTINUE (case-insensitive)
            decision = self._parse_termination_decision(response)

            if decision == "stop":
                logger.info(f"AI recommends stopping: {response[:200]}...")
                return False

            # Default to continuing if decision is "continue" or unrecognized
            logger.debug(f"AI recommends continuing: {response[:200]}...")
            return True

        except OllamaEngineError as e:
            logger.error(f"Termination evaluation failed: {e}")
            # Continue by default on error
            return True

    def _parse_termination_decision(self, response: str) -> str:
        """Parse explicit decision token from AI response.

        Looks for lines starting with STOP or CONTINUE (case-insensitive).
        Only stops when the decision is unambiguously STOP.

        Args:
            response: AI response text.

        Returns:
            "stop" if unambiguous STOP decision found, "continue" otherwise.
        """
        for line in response.split("\n"):
            line_stripped = line.strip().upper()
            # Check for lines that start with STOP or CONTINUE
            if line_stripped.startswith("STOP"):
                return "stop"
            if line_stripped.startswith("CONTINUE"):
                return "continue"

        # If no explicit decision token found, default to continue
        return "continue"

    # =========================================================================
    # VULNERABILITY MANAGEMENT
    # =========================================================================

    def _check_for_vulnerability(self, analysis: str) -> bool:
        """Check if AI analysis indicates a vulnerability was found.

        Args:
            analysis: AI analysis text.

        Returns:
            True if vulnerability indicators are present.
        """
        indicators = [
            "vulnerability found",
            "vulnerable",
            "security issue",
            "high confidence",
            "confirmed vulnerability",
            "exploitable",
            "severity: critical",
            "severity: high",
        ]
        analysis_lower = analysis.lower()
        return any(indicator in analysis_lower for indicator in indicators)

    def _parse_and_record_vulnerability(
        self,
        analysis: str,
        vuln_type: str,
        url: str,
        method: str,
        payload: Optional[str],
        response: HTTPResponse
    ) -> None:
        """Parse AI analysis and record discovered vulnerability.

        Args:
            analysis: AI analysis text containing vulnerability details.
            vuln_type: Category of vulnerability.
            url: Affected URL.
            method: HTTP method used.
            payload: Payload that triggered the vulnerability.
            response: HTTP response received.
        """
        # Extract severity from analysis
        severity = "Medium"  # Default
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            if sev.lower() in analysis.lower():
                severity = sev
                break

        # Extract confidence from analysis
        confidence = "Medium"  # Default
        for conf in ["High", "Medium", "Low"]:
            if f"confidence: {conf.lower()}" in analysis.lower():
                confidence = conf
                break

        # Create vulnerability record
        vulnerability = Vulnerability(
            type=vuln_type,
            severity=severity,
            confidence=confidence,
            evidence=truncate_body(response.body, 500),
            url=url,
            method=method,
            payload=payload,
            exploitation_steps=self._extract_exploitation_steps(analysis),
            recommendation=self._extract_recommendation(analysis)
        )

        self.vulnerabilities.append(vulnerability)

        logger.warning(
            f"Vulnerability found: [{severity}] {vuln_type} at {url}"
        )

    def _record_vulnerability(
        self,
        type: str,
        severity: str,
        confidence: str,
        evidence: str,
        url: str,
        method: str,
        payload: Optional[str] = None,
        exploitation_steps: Optional[str] = None,
        recommendation: Optional[str] = None
    ) -> None:
        """Record a discovered vulnerability.

        Args:
            type: Vulnerability category.
            severity: Severity level.
            confidence: Detection confidence.
            evidence: Response data showing the vulnerability.
            url: Affected endpoint.
            method: HTTP method used.
            payload: Test payload that triggered it.
            exploitation_steps: How to exploit.
            recommendation: Mitigation advice.
        """
        vulnerability = Vulnerability(
            type=type,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            url=url,
            method=method,
            payload=payload,
            exploitation_steps=exploitation_steps,
            recommendation=recommendation
        )
        self.vulnerabilities.append(vulnerability)
        logger.warning(f"Vulnerability recorded: [{severity}] {type} at {url}")

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def _construct_test_url(self, payload: str, endpoint: str = "/") -> str:
        """Construct a test URL with the given payload for a specific endpoint.

        Args:
            payload: Payload string to include in the URL.
            endpoint: The endpoint path to test (e.g., "/api/users").

        Returns:
            Constructed test URL.
        """
        # Build the base URL with the endpoint
        base_url = urljoin(self.target_url, endpoint)

        # Append payload as query parameter
        if "?" in base_url:
            return f"{base_url}&test={payload}"
        else:
            return f"{base_url}?test={payload}"

    def _extract_endpoints(self, response: HTTPResponse) -> List[str]:
        """Extract additional endpoints from response.

        Parses HTML/JSON responses for links, form actions, and API paths.
        Handles both absolute paths (/path) and relative paths (path.php).

        Args:
            response: HTTPResponse to analyze.

        Returns:
            List of discovered endpoint paths.
        """
        endpoints: List[str] = []
        body = response.body

        def normalize_path(path: str) -> Optional[str]:
            """Convert a path to absolute form, filtering out external URLs."""
            path = path.strip()
            # Skip empty, anchors, javascript, mailto, external URLs
            if not path or path.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                return None
            if path.startswith(('http://', 'https://')):
                # Check if same origin
                if path.startswith(self.target_url):
                    parsed = urlparse(path)
                    return parsed.path if parsed.path else None
                return None  # External URL
            # Absolute path
            if path.startswith('/'):
                return path
            # Relative path - convert to absolute
            return '/' + path

        # Extract href links
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, body, re.IGNORECASE)

        for href in hrefs:
            normalized = normalize_path(href)
            if normalized:
                endpoints.append(normalized)

        # Extract form actions
        action_pattern = r'action=["\']([^"\']+)["\']'
        actions = re.findall(action_pattern, body, re.IGNORECASE)

        for action in actions:
            normalized = normalize_path(action)
            if normalized:
                endpoints.append(normalized)

        # Extract src attributes (scripts, images that might reveal paths)
        src_pattern = r'src=["\']([^"\']+)["\']'
        srcs = re.findall(src_pattern, body, re.IGNORECASE)

        for src in srcs:
            normalized = normalize_path(src)
            if normalized and normalized.endswith(('.php', '.asp', '.aspx', '.jsp')):
                endpoints.append(normalized)

        # Extract API-like paths from JSON (capture full path, not just prefix)
        api_pattern = r'["\'](/(?:api|v[0-9]+)/[^"\']+)["\']'
        api_paths = re.findall(api_pattern, body, re.IGNORECASE)
        endpoints.extend(api_paths)

        # Deduplicate and sort for consistent ordering
        unique_endpoints = sorted(set(endpoints))

        logger.debug(f"Extracted {len(unique_endpoints)} endpoints from response")
        return unique_endpoints

    def _extract_forms(self, response: HTTPResponse, current_endpoint: str) -> List[FormData]:
        """Extract HTML forms from response for testing.

        Parses the HTML to find forms and their input fields, which are
        critical injection points for vulnerabilities like SQLi, XSS.

        Args:
            response: HTTPResponse containing HTML.
            current_endpoint: The endpoint where this response came from.

        Returns:
            List of FormData objects representing discovered forms.
        """
        forms: List[FormData] = []
        body = response.body

        # Match complete form tags with their content
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, body, re.IGNORECASE | re.DOTALL)

        for form_match in form_matches:
            form_tag_match = re.search(r'<form([^>]*)>', form_match.group(0), re.IGNORECASE)
            if not form_tag_match:
                continue

            form_attrs = form_tag_match.group(1)
            form_content = form_match.group(1)

            # Extract action (default to current endpoint if not specified)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            action = action_match.group(1) if action_match else current_endpoint

            # Normalize action to absolute path
            if action and not action.startswith('/'):
                if not action.startswith(('http://', 'https://')):
                    action = '/' + action

            # Extract method (default to GET)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract input fields
            inputs: Dict[str, str] = {}

            # Standard input fields
            input_pattern = r'<input([^>]*)>'
            for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                input_attrs = input_match.group(1)

                # Get input name
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                if not name_match:
                    continue
                name = name_match.group(1)

                # Get input type (skip submit, button, hidden for injection)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                input_type = type_match.group(1).lower() if type_match else "text"

                # Get default value
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                value = value_match.group(1) if value_match else ""

                # Include all inputs - we'll inject into text/password fields
                # but need hidden fields for CSRF tokens etc.
                inputs[name] = value

            # Also extract textarea fields
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
            for textarea_match in re.finditer(textarea_pattern, form_content, re.IGNORECASE):
                inputs[textarea_match.group(1)] = ""

            # Also extract select fields
            select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
            for select_match in re.finditer(select_pattern, form_content, re.IGNORECASE):
                inputs[select_match.group(1)] = ""

            if inputs:  # Only add forms that have input fields
                forms.append(FormData(
                    action=action,
                    method=method,
                    inputs=inputs,
                    endpoint=current_endpoint
                ))

        logger.debug(f"Extracted {len(forms)} forms from response")
        return forms

    def _parse_payloads(self, ai_response: str) -> List[Dict[str, str]]:
        """Parse AI response to extract payload information.

        Args:
            ai_response: AI response containing payload information.

        Returns:
            List of payload dictionaries.
        """
        payloads: List[Dict[str, str]] = []

        # Look for **Payload**: pattern
        payload_pattern = r'\*\*Payload\*\*:\s*[`"]?([^`"\n]+)[`"]?'
        purpose_pattern = r'\*\*Purpose\*\*:\s*([^\n]+)'
        expected_pattern = r'\*\*Expected Response\*\*:\s*([^\n]+)'

        # Find all payloads
        payload_matches = re.findall(payload_pattern, ai_response)
        purpose_matches = re.findall(purpose_pattern, ai_response)
        expected_matches = re.findall(expected_pattern, ai_response)

        for i, payload in enumerate(payload_matches):
            payload_info = {
                "payload": payload.strip(),
                "purpose": purpose_matches[i].strip() if i < len(purpose_matches) else "Unknown",
                "expected_response": expected_matches[i].strip() if i < len(expected_matches) else "Unknown"
            }
            payloads.append(payload_info)

        # Fallback: try to find code blocks with payloads
        if not payloads:
            code_pattern = r'```[^\n]*\n([^`]+)```'
            code_blocks = re.findall(code_pattern, ai_response)
            for block in code_blocks:
                for line in block.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append({
                            "payload": line,
                            "purpose": "Extracted from code block",
                            "expected_response": "Unknown"
                        })

        logger.debug(f"Parsed {len(payloads)} payloads from AI response")
        return payloads[:10]  # Limit to 10 payloads

    def _extract_exploitation_steps(self, analysis: str) -> Optional[str]:
        """Extract exploitation steps from AI analysis.

        Args:
            analysis: AI analysis text.

        Returns:
            Exploitation steps if found, None otherwise.
        """
        pattern = r'\*\*Exploitation Steps\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)'
        match = re.search(pattern, analysis, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _extract_recommendation(self, analysis: str) -> Optional[str]:
        """Extract recommendation from AI analysis.

        Args:
            analysis: AI analysis text.

        Returns:
            Recommendation if found, None otherwise.
        """
        patterns = [
            r'\*\*Recommended Fix\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)',
            r'\*\*Recommendation\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)',
            r'\*\*Mitigation\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)',
        ]
        for pattern in patterns:
            match = re.search(pattern, analysis, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _format_technology_hints(self) -> str:
        """Format detected technology hints as a string.

        Returns:
            Formatted technology hints or "Unknown".
        """
        if not self.detected_technology:
            return "Unknown"

        return ", ".join(
            f"{key}: {value}"
            for key, value in self.detected_technology.items()
        )

    def _format_recent_results(self) -> str:
        """Format recent test results for self-termination evaluation.

        Returns:
            Formatted summary of recent results.
        """
        recent = self.test_results[-SELF_TERMINATION_WINDOW:]
        if not recent:
            return "No recent results"

        lines = []
        for result in recent:
            status = "FINDING" if result.finding else "clean"
            lines.append(
                f"- {result.vulnerability_type}: {status} "
                f"(status {result.response.status_code})"
            )

        return "\n".join(lines)

    def _trim_conversation_history(self, max_messages: int = 20) -> None:
        """Trim conversation history to prevent token overflow.

        Keeps the system prompt and recent messages.

        Args:
            max_messages: Maximum number of messages to keep.
        """
        if len(self.conversation_history) <= max_messages:
            return

        # Keep system prompt and most recent messages
        system_prompt = self.conversation_history[0]
        recent_messages = self.conversation_history[-(max_messages - 1):]
        self.conversation_history = [system_prompt] + recent_messages

        logger.debug(
            f"Trimmed conversation history to {len(self.conversation_history)} messages"
        )

    # =========================================================================
    # EXPLOITATION PHASE
    # =========================================================================

    def _exploitation_phase(self, sqli_vulns: List[Vulnerability]) -> None:
        """Exploit confirmed SQL injection vulnerabilities to extract data.

        Args:
            sqli_vulns: List of confirmed SQLi vulnerabilities.
        """
        for vuln in sqli_vulns:
            logger.info(f"Exploiting SQLi at {vuln.url}")

            try:
                # Extract credentials via SQLi
                credentials = self._exploit_sqli_for_credentials(vuln)

                if credentials:
                    self.extracted_credentials.extend(credentials)
                    logger.info(f"Extracted {len(credentials)} credentials")

                    # Try to login with extracted credentials
                    if self._attempt_login_with_credentials(credentials):
                        logger.info(f"Successfully logged in as {self.auth_user}")
                        break

            except Exception as e:
                logger.error(f"Exploitation failed: {e}")
                continue

    def _exploit_sqli_for_credentials(
        self,
        vuln: Vulnerability
    ) -> List[Dict[str, str]]:
        """Exploit SQLi to extract user credentials.

        Args:
            vuln: The SQLi vulnerability to exploit.

        Returns:
            List of credential dictionaries with username/password.
        """
        credentials: List[Dict[str, str]] = []

        # Determine database type from technology hints
        db_type = self.detected_technology.get("database", "MySQL")

        # Get AI to generate exploitation payloads
        prompt = format_prompt(
            SQLI_EXPLOITATION_PROMPT,
            target_url=vuln.url,
            method=vuln.method,
            parameter=self._extract_parameter_from_payload(vuln.payload or ""),
            confirmed_payload=vuln.payload or "",
            db_type=db_type,
            previous_response=vuln.evidence[:1000]
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            ai_response = self._ai_client.chat_with_retry(messages)
            payloads = self._parse_exploitation_payloads(ai_response)

            # Execute each payload step
            for step in payloads:
                payload = step.get("payload", "")
                if not payload:
                    continue

                # Send the exploitation payload
                response = self._send_exploitation_request(vuln, payload)
                self.request_count += 1

                # Parse credentials from response
                found_creds = self._parse_credentials_from_response(response)
                if found_creds:
                    credentials.extend(found_creds)
                    self.exploitation_results.append({
                        "step": step.get("purpose", "Unknown"),
                        "payload": payload,
                        "credentials_found": len(found_creds)
                    })

        except OllamaEngineError as e:
            logger.error(f"AI exploitation planning failed: {e}")

        return credentials

    def _send_exploitation_request(
        self,
        vuln: Vulnerability,
        payload: str
    ) -> HTTPResponse:
        """Send an exploitation payload request.

        Args:
            vuln: Original vulnerability info.
            payload: Exploitation payload to send.

        Returns:
            HTTP response from the exploitation attempt.
        """
        # Find the form that was vulnerable
        form = None
        for f in self.discovered_forms:
            if f.action in vuln.url:
                form = f
                break

        if form and vuln.method.upper() == "POST":
            # POST to form with payload
            form_data = dict(form.inputs)
            param_name = self._extract_parameter_from_payload(vuln.payload or "")
            if param_name and param_name in form_data:
                form_data[param_name] = payload
            else:
                # Inject into first field
                first_field = list(form_data.keys())[0] if form_data else "id"
                form_data[first_field] = payload

            return self._http_client.send_request(
                url=vuln.url,
                method="POST",
                body=form_data,
                form_data=True
            )
        else:
            # GET request with payload in URL
            if "?" in vuln.url:
                test_url = vuln.url.split("?")[0] + "?" + payload
            else:
                test_url = vuln.url + "?" + payload

            return self._http_client.send_request(url=test_url, method="GET")

    def _parse_exploitation_payloads(
        self,
        ai_response: str
    ) -> List[Dict[str, str]]:
        """Parse exploitation steps from AI response.

        Args:
            ai_response: AI response with exploitation steps.

        Returns:
            List of step dictionaries with payload, purpose, etc.
        """
        steps: List[Dict[str, str]] = []

        # Look for ### Step N: pattern
        step_pattern = r'###\s*Step\s*\d+[:\s]*([^\n]*)\n(.*?)(?=###\s*Step|\Z)'
        matches = re.findall(step_pattern, ai_response, re.DOTALL | re.IGNORECASE)

        for desc, content in matches:
            # Extract payload from step content
            payload_match = re.search(
                r'\*\*Payload\*\*:\s*[`"]?([^`"\n]+)[`"]?',
                content
            )
            purpose_match = re.search(
                r'\*\*Purpose\*\*:\s*([^\n]+)',
                content
            )

            if payload_match:
                steps.append({
                    "description": desc.strip(),
                    "payload": payload_match.group(1).strip(),
                    "purpose": purpose_match.group(1).strip() if purpose_match else desc.strip()
                })

        # Fallback: look for any SQL-like payloads
        if not steps:
            sql_patterns = [
                r"(?:UNION\s+SELECT[^'\"]+)",
                r"(?:'\s*OR\s+'[^']+'\s*=\s*'[^']+')",
                r"(?:admin'--)",
            ]
            for pattern in sql_patterns:
                matches = re.findall(pattern, ai_response, re.IGNORECASE)
                for match in matches:
                    steps.append({
                        "description": "Extracted SQL payload",
                        "payload": match.strip(),
                        "purpose": "SQL Injection exploitation"
                    })

        return steps

    def _parse_credentials_from_response(
        self,
        response: HTTPResponse
    ) -> List[Dict[str, str]]:
        """Parse credentials from SQLi exploitation response.

        Args:
            response: HTTP response that may contain credential data.

        Returns:
            List of credential dictionaries.
        """
        credentials: List[Dict[str, str]] = []
        body = response.body

        # Common patterns for exposed credentials
        # Pattern: admin:5f4dcc3b5aa765d61d8327deb882cf99
        user_hash_pattern = r'(\w+)[:\s]+([a-f0-9]{32,64})'
        matches = re.findall(user_hash_pattern, body, re.IGNORECASE)
        for username, password_hash in matches:
            if username.lower() not in ["id", "user_id", "type", "name"]:
                credentials.append({
                    "username": username,
                    "password_hash": password_hash,
                    "password": self._crack_common_hash(password_hash)
                })

        # Pattern: username in one cell, hash in next
        # Look for table-like structures
        td_pattern = r'<td>([^<]+)</td>\s*<td>([^<]+)</td>'
        td_matches = re.findall(td_pattern, body, re.IGNORECASE)
        for val1, val2 in td_matches:
            # Check if val2 looks like a hash
            if re.match(r'^[a-f0-9]{32,64}$', val2.strip(), re.IGNORECASE):
                credentials.append({
                    "username": val1.strip(),
                    "password_hash": val2.strip(),
                    "password": self._crack_common_hash(val2.strip())
                })

        return credentials

    def _crack_common_hash(self, hash_value: str) -> Optional[str]:
        """Try to crack common password hashes.

        Args:
            hash_value: Hash value to crack.

        Returns:
            Cracked password or None.
        """
        # Common MD5 hashes
        common_hashes = {
            "5f4dcc3b5aa765d61d8327deb882cf99": "password",
            "e99a18c428cb38d5f260853678922e03": "abc123",
            "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
            "25d55ad283aa400af464c76d713c07ad": "12345678",
            "e10adc3949ba59abbe56e057f20f883e": "123456",
            "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
            "8d3533d75ae2c3966d7e0d4fcc69216b": "charley",
        }
        return common_hashes.get(hash_value.lower())

    def _extract_parameter_from_payload(self, payload: str) -> str:
        """Extract parameter name from a payload string like 'username=value'.

        Args:
            payload: Payload string.

        Returns:
            Parameter name or empty string.
        """
        if "=" in payload:
            return payload.split("=")[0]
        return ""

    def _attempt_login_with_credentials(
        self,
        credentials: List[Dict[str, str]]
    ) -> bool:
        """Attempt to login using extracted credentials.

        Args:
            credentials: List of credential dictionaries.

        Returns:
            True if login successful.
        """
        # Find login form
        login_form = None
        for form in self.discovered_forms:
            form_inputs_lower = [k.lower() for k in form.inputs.keys()]
            if "password" in form_inputs_lower or "pass" in form_inputs_lower:
                login_form = form
                break

        if not login_form:
            logger.warning("No login form found for credential testing")
            return False

        # Sort credentials - prefer admin-like usernames
        sorted_creds = sorted(
            credentials,
            key=lambda c: 0 if "admin" in c.get("username", "").lower() else 1
        )

        for cred in sorted_creds:
            username = cred.get("username", "")
            password = cred.get("password") or cred.get("password_hash", "")

            if not username or not password:
                continue

            logger.info(f"Attempting login as: {username}")

            try:
                # Build form data
                form_data = dict(login_form.inputs)

                # Find username and password fields
                for field_name in form_data.keys():
                    field_lower = field_name.lower()
                    if field_lower in ["username", "user", "login", "email"]:
                        form_data[field_name] = username
                    elif field_lower in ["password", "pass", "pwd"]:
                        form_data[field_name] = password

                # Get CSRF token if needed
                login_url = urljoin(self.target_url, login_form.action)
                pre_response = self._http_client.send_request(login_url, method="GET")
                self.request_count += 1

                # Extract fresh CSRF token
                token_match = re.search(
                    r"name=['\"]?user_token['\"]?\s+value=['\"]?([^'\"]+)['\"]?",
                    pre_response.body
                )
                if token_match:
                    form_data["user_token"] = token_match.group(1)

                # Submit login
                response = self._http_client.send_request(
                    url=login_url,
                    method=login_form.method,
                    body=form_data,
                    form_data=True
                )
                self.request_count += 1

                # Check if login succeeded
                if self._check_login_success(response):
                    self.authenticated = True
                    self.auth_user = username
                    return True

            except HTTPClientError as e:
                logger.debug(f"Login attempt failed: {e}")
                continue

        return False

    def _check_login_success(self, response: HTTPResponse) -> bool:
        """Check if login was successful based on response.

        Args:
            response: HTTP response after login attempt.

        Returns:
            True if login appears successful.
        """
        body_lower = response.body.lower()

        # Positive indicators
        success_indicators = [
            "welcome",
            "dashboard",
            "logout",
            "my account",
            "logged in",
            "sign out",
        ]

        # Negative indicators
        failure_indicators = [
            "login failed",
            "invalid",
            "incorrect",
            "try again",
            "error",
        ]

        has_success = any(ind in body_lower for ind in success_indicators)
        has_failure = any(ind in body_lower for ind in failure_indicators)

        # Also check if we're not on login page anymore
        not_on_login = "login.php" not in response.url.lower()

        return has_success and not has_failure and not_on_login

