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
    ATTACK_VECTOR_ANALYSIS_PROMPT,
    SMART_ATTACK_PROMPT,
    KATANA_RESULTS_ANALYSIS_PROMPT,
    format_prompt,
)
from scanner.katana_client import (
    KatanaClient,
    KatanaNotInstalledError,
    KatanaExecutionError,
    KatanaTimeoutError,
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


@dataclass
class AttackVector:
    """Represents a discovered attack surface to be tested.

    This dataclass captures information about a potential attack point
    discovered during the reconnaissance phase. The LLM analyzes each
    element and suggests what attack types would be effective.

    Attributes:
        id: Unique identifier for this attack vector.
        url: The URL where this attack vector exists.
        endpoint: The endpoint path.
        method: HTTP method to use (GET/POST).
        element_type: Type of element (form, url_param, header, cookie, etc.).
        element_name: Name of the element (e.g., input field name).
        element_context: Description of what this element appears to do.
        suggested_attacks: List of attack types the LLM suggests for this vector.
        priority: Priority level (1=highest, 5=lowest) based on likelihood of vulnerability.
        form_data: Associated FormData if this is a form-based vector.
        status: Current status (pending, testing, completed, skipped).
        tested_attacks: List of attack types already tested against this vector.
        findings: List of vulnerabilities found on this vector.
    """
    id: str
    url: str
    endpoint: str
    method: str
    element_type: str
    element_name: str
    element_context: str
    suggested_attacks: List[str]
    priority: int = 3
    form_data: Optional[FormData] = None
    status: str = "pending"
    tested_attacks: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    endpoint_category: Optional[str] = None
    katana_priority_level: Optional[str] = None  # high_priority, medium_priority, low_priority

    def to_dict(self) -> Dict[str, Any]:
        """Convert attack vector to dictionary format."""
        return {
            "id": self.id,
            "url": self.url,
            "endpoint": self.endpoint,
            "method": self.method,
            "element_type": self.element_type,
            "element_name": self.element_name,
            "element_context": self.element_context,
            "suggested_attacks": self.suggested_attacks,
            "priority": self.priority,
            "status": self.status,
            "tested_attacks": self.tested_attacks,
            "findings": self.findings,
            "endpoint_category": self.endpoint_category,
            "katana_priority_level": self.katana_priority_level,
        }


class ScanPhase:
    """Enum-like class for scan phases."""
    INITIALIZING = "initializing"
    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    ATTACK = "attack"
    EXPLOITATION = "exploitation"
    COMPLETE = "complete"


@dataclass
class ScanProgress:
    """Tracks the overall progress of the scan.

    Provides real-time visibility into what the scanner is doing
    and how far through the process it is.

    Attributes:
        phase: Current scan phase (discovery, analysis, attack, etc.).
        phase_progress: Progress within current phase (0-100).
        total_endpoints_found: Number of endpoints discovered.
        total_forms_found: Number of forms discovered.
        total_attack_vectors: Total attack vectors identified.
        attack_vectors_completed: Number of attack vectors fully tested.
        attack_vectors_in_progress: Currently being tested.
        current_vector: Description of current attack vector being tested.
        current_attack_type: Type of attack currently being executed.
        vulnerabilities_found: Total vulnerabilities found so far.
        requests_sent: Total HTTP requests sent.
        start_time: When the scan started.
        last_update_time: When progress was last updated.
        status_message: Human-readable status message.
        katana_endpoints_discovered: Endpoints discovered by Katana.
        katana_scan_active: Whether a Katana scan is currently running.
    """
    phase: str = ScanPhase.INITIALIZING
    phase_progress: float = 0.0
    total_endpoints_found: int = 0
    total_forms_found: int = 0
    total_attack_vectors: int = 0
    attack_vectors_completed: int = 0
    attack_vectors_in_progress: int = 0
    current_vector: str = ""
    current_attack_type: str = ""
    vulnerabilities_found: int = 0
    requests_sent: int = 0
    start_time: Optional[float] = None
    last_update_time: Optional[float] = None
    status_message: str = "Initializing..."
    katana_endpoints_discovered: int = 0
    katana_scan_active: bool = False
    katana_current_url: str = ""
    katana_crawl_depth_current: int = 0
    katana_crawl_depth_max: int = 0
    katana_status_phase: str = ""

    def get_overall_progress(self) -> float:
        """Calculate overall scan progress percentage."""
        phase_weights = {
            ScanPhase.INITIALIZING: 0,
            ScanPhase.DISCOVERY: 10,
            ScanPhase.ANALYSIS: 20,
            ScanPhase.ATTACK: 90,
            ScanPhase.EXPLOITATION: 98,
            ScanPhase.COMPLETE: 100,
        }
        base_progress = phase_weights.get(self.phase, 0)

        if self.phase == ScanPhase.DISCOVERY:
            # Discovery phase contributes 10%
            return base_progress + (self.phase_progress * 0.1)
        elif self.phase == ScanPhase.ANALYSIS:
            # Analysis phase contributes 10% (from 10 to 20)
            return base_progress + (self.phase_progress * 0.1)
        elif self.phase == ScanPhase.ATTACK:
            # Attack phase contributes 70% (from 20 to 90)
            if self.total_attack_vectors > 0:
                attack_progress = (
                    self.attack_vectors_completed / self.total_attack_vectors
                ) * 100
                return 20 + (attack_progress * 0.7)
            return 20
        elif self.phase == ScanPhase.EXPLOITATION:
            # Exploitation phase contributes 8% (from 90 to 98)
            return base_progress + (self.phase_progress * 0.08)

        return base_progress

    def to_dict(self) -> Dict[str, Any]:
        """Convert progress to dictionary format."""
        elapsed = 0
        if self.start_time:
            elapsed = time.time() - self.start_time

        return {
            "phase": self.phase,
            "phase_progress": round(self.phase_progress, 1),
            "overall_progress": round(self.get_overall_progress(), 1),
            "total_endpoints_found": self.total_endpoints_found,
            "total_forms_found": self.total_forms_found,
            "total_attack_vectors": self.total_attack_vectors,
            "attack_vectors_completed": self.attack_vectors_completed,
            "attack_vectors_pending": (
                self.total_attack_vectors - self.attack_vectors_completed
            ),
            "current_vector": self.current_vector,
            "current_attack_type": self.current_attack_type,
            "vulnerabilities_found": self.vulnerabilities_found,
            "requests_sent": self.requests_sent,
            "elapsed_seconds": round(elapsed, 1),
            "status_message": self.status_message,
            "katana_endpoints_discovered": self.katana_endpoints_discovered,
            "katana_scan_active": self.katana_scan_active,
            "katana_current_url": self.katana_current_url,
            "katana_crawl_depth_current": self.katana_crawl_depth_current,
            "katana_crawl_depth_max": self.katana_crawl_depth_max,
            "katana_status_phase": self.katana_status_phase,
        }

    def format_status_line(self) -> str:
        """Format a single-line status for console display."""
        progress = self.get_overall_progress()
        if self.phase == ScanPhase.INITIALIZING:
            return f"[{progress:5.1f}%] 🚀 Initializing scan..."
        elif self.phase == ScanPhase.DISCOVERY:
            # Show Katana-specific status based on phase
            if self.katana_scan_active and self.katana_status_phase == "initializing":
                return (
                    f"[{progress:5.1f}%] 🚀 Discovery: "
                    f"Initializing Katana headless browser..."
                )
            if self.katana_scan_active and self.katana_status_phase == "crawling":
                # Truncate current URL for display
                url_display = self.katana_current_url[:50]
                if len(self.katana_current_url) > 50:
                    url_display += "..."
                depth_info = ""
                if self.katana_crawl_depth_max > 0:
                    depth_info = (
                        f"depth {self.katana_crawl_depth_current}/"
                        f"{self.katana_crawl_depth_max} | "
                    )
                return (
                    f"[{progress:5.1f}%] 🕷️ Discovery: Katana crawling ({depth_info}"
                    f"{self.katana_endpoints_discovered} endpoints) | {url_display}"
                )
            if self.katana_scan_active and self.katana_status_phase == "parsing":
                return (
                    f"[{progress:5.1f}%] 📋 Discovery: Parsing Katana results... "
                    f"{self.katana_endpoints_discovered} endpoints found"
                )
            if self.katana_status_phase == "extracting_forms":
                return (
                    f"[{progress:5.1f}%] 📝 Discovery: "
                    f"Extracting forms from {self.katana_endpoints_discovered} "
                    f"Katana endpoints..."
                )
            # Fallback for legacy katana_scan_active without phase
            if self.katana_scan_active:
                return (
                    f"[{progress:5.1f}%] 🔍 Discovery: Katana scanning... "
                    f"{self.katana_endpoints_discovered} endpoints found"
                )
            # Show status message during initial discovery, then show counts
            if self.total_endpoints_found == 0 and self.total_forms_found == 0:
                return f"[{progress:5.1f}%] 🔍 Discovery: {self.status_message}"
            # Show form extraction progress if Katana was used
            if self.katana_endpoints_discovered > 0:
                return (
                    f"[{progress:5.1f}%] 🔍 Discovery: "
                    f"Extracting forms from {self.total_endpoints_found} Katana endpoints, "
                    f"{self.total_forms_found} forms"
                )
            return (
                f"[{progress:5.1f}%] 🔍 Discovery: "
                f"Found {self.total_endpoints_found} endpoints, "
                f"{self.total_forms_found} forms"
            )
        elif self.phase == ScanPhase.ANALYSIS:
            return (
                f"[{progress:5.1f}%] 🧠 Analysis: "
                f"Identified {self.total_attack_vectors} attack vectors"
            )
        elif self.phase == ScanPhase.ATTACK:
            return (
                f"[{progress:5.1f}%] ⚔️  Attack: "
                f"{self.attack_vectors_completed}/{self.total_attack_vectors} vectors | "
                f"🎯 {self.vulnerabilities_found} vulns | "
                f"Testing: {self.current_vector[:40]}..."
            )
        elif self.phase == ScanPhase.EXPLOITATION:
            return (
                f"[{progress:5.1f}%] 💉 Exploitation: {self.status_message}"
            )
        elif self.phase == ScanPhase.COMPLETE:
            return (
                f"[100.0%] ✅ Complete: "
                f"Found {self.vulnerabilities_found} vulnerabilities"
            )
        return f"[{progress:5.1f}%] {self.status_message}"


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
        progress_callback: Optional[callable] = None,
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
            progress_callback: Optional callback function(ScanProgress) for progress updates.

        Raises:
            OllamaEngineError: If the LLM provider is not available.
        """
        self.target_url = target_url.rstrip("/")
        self.max_requests = max_requests
        self._progress_callback = progress_callback

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

        # Katana client for endpoint discovery
        self._katana_client = KatanaClient()
        self._katana_available: bool = False
        self._katana_analysis_results: Dict[str, Any] = {}

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

        # NEW: Attack vector discovery and tracking
        self.attack_vectors: List[AttackVector] = []  # All discovered attack vectors
        self._attack_vector_id_counter: int = 0

        # NEW: Scan progress tracking
        self.progress = ScanProgress()

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

    def _update_progress(
        self,
        phase: Optional[str] = None,
        status_message: Optional[str] = None,
        **kwargs
    ) -> None:
        """Update scan progress and notify callback.

        Args:
            phase: New scan phase (if changing).
            status_message: Human-readable status message.
            **kwargs: Additional progress attributes to update.
        """
        if phase:
            self.progress.phase = phase
        if status_message:
            self.progress.status_message = status_message

        # Update any additional attributes
        for key, value in kwargs.items():
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)

        self.progress.requests_sent = self.request_count
        self.progress.vulnerabilities_found = len(self.vulnerabilities)
        self.progress.last_update_time = time.time()

        # Notify callback if registered
        if self._progress_callback:
            try:
                self._progress_callback(self.progress)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")

    def _generate_attack_vector_id(self) -> str:
        """Generate a unique ID for an attack vector."""
        self._attack_vector_id_counter += 1
        return f"av_{self._attack_vector_id_counter:04d}"

    def scan(self) -> Dict[str, Any]:
        """Execute the complete DAST scanning workflow.

        The scan follows these phases:
        1. DISCOVERY: Crawl the application and find all endpoints, forms, parameters
        2. ANALYSIS: LLM analyzes discovered elements and identifies attack vectors
        3. ATTACK: Systematically test each attack vector with appropriate payloads
        4. EXPLOITATION: If SQLi found, attempt to extract data

        Returns:
            Dictionary containing:
                - vulnerabilities: List of discovered vulnerabilities
                - statistics: Scan statistics (requests, duration, etc.)
                - model_info: AI model information
                - tested_vectors: Attack types tested
                - target_url: Scanned URL
                - technology_hints: Detected technology stack
                - attack_vectors: All discovered attack vectors

        Example:
            >>> results = scanner.scan()
            >>> for vuln in results["vulnerabilities"]:
            ...     print(f"[{vuln['severity']}] {vuln['type']}")
        """
        self.start_time = time.time()
        self.progress.start_time = self.start_time
        logger.info(f"Starting DAST scan of {self.target_url}")
        self._update_progress(
            phase=ScanPhase.INITIALIZING,
            status_message="Starting scan..."
        )

        try:
            # Phase 1: Discovery - Crawl and find all elements
            logger.info("Phase 1: Discovery - Crawling application...")
            self._update_progress(
                phase=ScanPhase.DISCOVERY,
                status_message="Crawling application to discover endpoints and forms..."
            )
            self._discovery_phase()

            # Phase 2: Analysis - LLM identifies attack vectors
            logger.info("Phase 2: Analysis - Identifying attack vectors...")
            self._update_progress(
                phase=ScanPhase.ANALYSIS,
                status_message="Analyzing discovered elements for attack vectors..."
            )
            self._analysis_phase()

            # Phase 3: Attack - Systematically test each vector
            logger.info(f"Phase 3: Attack - Testing {len(self.attack_vectors)} vectors...")
            self._update_progress(
                phase=ScanPhase.ATTACK,
                status_message=f"Testing {len(self.attack_vectors)} attack vectors..."
            )
            self._attack_phase()

            # Phase 4: Exploitation (if SQLi found)
            sqli_vulns = [v for v in self.vulnerabilities if "sql" in v.type.lower()]
            if sqli_vulns:
                logger.info("Phase 4: Exploiting SQL Injection vulnerabilities...")
                self._update_progress(
                    phase=ScanPhase.EXPLOITATION,
                    status_message="Exploiting confirmed SQL injection..."
                )
                self._exploitation_phase(sqli_vulns)

            # Mark complete
            self._update_progress(
                phase=ScanPhase.COMPLETE,
                status_message=f"Scan complete. Found {len(self.vulnerabilities)} vulnerabilities."
            )

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

        # Count attack vector statistics
        vectors_completed = sum(
            1 for v in self.attack_vectors if v.status == "completed"
        )
        vectors_with_findings = sum(
            1 for v in self.attack_vectors if v.findings
        )

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
                # New attack vector statistics
                "attack_vectors_identified": len(self.attack_vectors),
                "attack_vectors_tested": vectors_completed,
                "attack_vectors_vulnerable": vectors_with_findings,
                "forms_discovered": len(self.discovered_forms),
                # Katana statistics
                "katana_used": (
                    self._katana_available
                    and self.progress.katana_endpoints_discovered > 0
                ),
                "katana_endpoints_discovered": self.progress.katana_endpoints_discovered,
            },
            "model_info": self._ai_client.get_model_info(),
            "tested_vectors": self.tested_vectors,
            "technology_hints": self.detected_technology,
            "attack_vectors": [av.to_dict() for av in self.attack_vectors],
            "progress": self.progress.to_dict(),
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

    def _perform_reconnaissance(self) -> Optional[HTTPResponse]:
        """Perform initial reconnaissance on the target.

        Sends initial request to gather technology hints and
        identify potential entry points for testing.

        Returns:
            The initial HTTPResponse from the target (for potential re-use
            if Katana fails and we need to extract endpoints later).
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

            # Always extract and queue endpoints from the initial response
            # This ensures manual crawling has seeds even if Katana fails at runtime
            initial_endpoints = self._extract_endpoints(response)

            # Always queue endpoints - provides baseline coverage even if Katana
            # partially succeeds or fails. Katana will discover more anyway.
            for endpoint in initial_endpoints:
                if endpoint not in self.tested_endpoints:
                    self.pending_endpoints.add(endpoint)

            if self._katana_available:
                logger.info(
                    f"Reconnaissance complete. "
                    f"Found {len(initial_endpoints)} potential endpoints, "
                    f"{len(self.discovered_forms)} forms. "
                    f"Katana will discover additional endpoints."
                )
            else:
                logger.info(
                    f"Reconnaissance complete. "
                    f"Found {len(initial_endpoints)} potential endpoints, "
                    f"{len(self.discovered_forms)} forms, "
                    f"{len(self.pending_endpoints)} queued for testing."
                )

            # Return response for potential later use if Katana fails
            return response

        except HTTPClientError as e:
            logger.error(f"Reconnaissance failed: {e}")
            raise

    # =========================================================================
    # NEW PHASE METHODS
    # =========================================================================

    def _discovery_phase(self) -> None:
        """Phase 1: Discover all endpoints, forms, and potential attack surfaces.

        Uses Katana for comprehensive endpoint discovery when available,
        with fallback to manual breadth-first crawling. Extracts:
        - All reachable endpoints
        - Forms with their input fields
        - URL parameters
        - Technology hints
        """
        # Phase 1: Check Katana availability
        self._update_progress(
            status_message="Checking Katana availability...",
            phase_progress=5.0
        )

        try:
            self._katana_available = self._katana_client.is_katana_installed()
        except Exception as e:
            logger.warning(f"Error checking Katana availability: {e}")
            self._katana_available = False

        if self._katana_available:
            logger.info("Katana is available - will use for endpoint discovery")
        else:
            logger.warning(
                "Katana not available - falling back to manual crawling. "
                "Install Katana for better coverage: brew install katana"
            )

        # Phase 2: Perform initial reconnaissance
        # Store the response so we can re-extract endpoints if Katana fails
        initial_response = self._perform_reconnaissance()

        # Update progress with initial findings
        self._update_progress(
            total_endpoints_found=len(self.tested_endpoints) + len(self.pending_endpoints),
            total_forms_found=len(self.discovered_forms),
            phase_progress=10.0
        )

        # Track whether we need to fall back to manual crawling
        use_manual_crawling = not self._katana_available
        katana_endpoints: List[str] = []

        # Phase 3: Run Katana scan (if available)
        if self._katana_available:
            try:
                # Update progress with initialization phase
                self._update_progress(
                    katana_scan_active=True,
                    katana_status_phase="initializing",
                    katana_crawl_depth_max=self._katana_client.depth,
                    status_message="Initializing Katana headless browser...",
                    phase_progress=15.0
                )

                # Create a progress callback for streaming updates
                def katana_progress_callback(endpoint_count: int, current_url: str) -> None:
                    """Callback for real-time Katana progress updates."""
                    # Calculate depth from URL path
                    try:
                        parsed_url = urlparse(current_url)
                        path_segments = [s for s in parsed_url.path.split('/') if s]
                        current_depth = len(path_segments)
                    except Exception:
                        current_depth = 0

                    # Progress from 15% to 45% during crawling
                    crawl_progress = 15.0 + min(30.0, endpoint_count * 0.5)

                    self._update_progress(
                        katana_scan_active=True,
                        katana_status_phase="crawling",
                        katana_endpoints_discovered=endpoint_count,
                        katana_current_url=current_url,
                        katana_crawl_depth_current=current_depth,
                        phase_progress=crawl_progress,
                        status_message=f"Katana crawling: {endpoint_count} endpoints found"
                    )

                # Run streaming Katana scan
                katana_endpoints = self._katana_client.run_scan_streaming(
                    self.target_url,
                    progress_callback=katana_progress_callback
                )
                logger.info(f"Katana discovered {len(katana_endpoints)} endpoints")

                # Update with parsing phase
                self._update_progress(
                    katana_scan_active=True,
                    katana_status_phase="parsing",
                    katana_endpoints_discovered=len(katana_endpoints),
                    phase_progress=45.0,
                    status_message=f"Parsing {len(katana_endpoints)} Katana results..."
                )

                # Phase 4: Process Katana results - convert URLs to relative paths
                for endpoint in katana_endpoints:
                    parsed = urlparse(endpoint)
                    # Extract path, preserving query parameters for testing
                    path = parsed.path or "/"
                    if parsed.query:
                        path = f"{path}?{parsed.query}"
                    if path not in self.tested_endpoints:
                        self.pending_endpoints.add(path)

                # Update with AI analysis phase
                self._update_progress(
                    katana_scan_active=False,
                    katana_status_phase="ai_analyzing",
                    katana_endpoints_discovered=len(katana_endpoints),
                    katana_current_url="",
                    total_endpoints_found=len(katana_endpoints),
                    phase_progress=50.0,
                    status_message=f"AI analyzing {len(katana_endpoints)} Katana results..."
                )

                # Analyze Katana endpoints using AI for categorization
                self._katana_analysis_results = self._analyze_katana_endpoints(
                    katana_endpoints
                )

                # Update with form extraction phase
                self._update_progress(
                    katana_status_phase="extracting_forms",
                    phase_progress=55.0,
                    status_message=f"Extracting forms from {len(katana_endpoints)} endpoints"
                )

            except KatanaNotInstalledError as e:
                logger.warning(
                    f"⚠️ Katana not installed - falling back to manual crawling. {e}"
                )
                self._katana_available = False
                use_manual_crawling = True
                self._update_progress(
                    katana_scan_active=False,
                    katana_status_phase="",
                    katana_current_url=""
                )
            except KatanaTimeoutError as e:
                logger.error(
                    f"⏱️ Katana scan timed out: {e}. "
                    f"Consider reducing KATANA_DEPTH or increasing KATANA_TIMEOUT in config"
                )
                self._katana_available = False
                use_manual_crawling = True
                self._update_progress(
                    katana_scan_active=False,
                    katana_status_phase="",
                    katana_current_url=""
                )
            except KatanaExecutionError as e:
                logger.error(f"❌ Katana execution failed - falling back to manual crawling: {e}")
                logger.debug(f"Katana execution error details: {e}")
                self._katana_available = False
                use_manual_crawling = True
                self._update_progress(
                    katana_scan_active=False,
                    katana_status_phase="",
                    katana_current_url=""
                )
            except Exception as e:
                logger.error(f"🔧 Unexpected Katana error - falling back to manual crawling: {e}")
                logger.debug(f"Unexpected Katana error details: {e}", exc_info=True)
                self._katana_available = False
                use_manual_crawling = True
                self._update_progress(
                    katana_scan_active=False,
                    katana_status_phase="",
                    katana_current_url=""
                )

        # Phase 5: Extract forms from Katana-discovered endpoints
        if katana_endpoints and not use_manual_crawling:
            self._extract_forms_from_endpoints()
        elif use_manual_crawling:
            # FALLBACK: Manual breadth-first crawling
            # This code runs only if Katana is unavailable or fails
            # Katana provides superior coverage with headless browser support
            if self._katana_available is False and katana_endpoints == []:
                # Katana was available but failed at runtime
                logger.warning(
                    "Katana failed at runtime, falling back to manual crawling "
                    f"with {len(self.pending_endpoints)} root-extracted seeds"
                )
            else:
                # Katana was never available
                logger.warning(
                    f"Katana unavailable, using manual crawling "
                    f"with {len(self.pending_endpoints)} seeds"
                )

            # Safety net: Re-populate pending_endpoints from initial response if empty
            # This should rarely happen now since recon always queues endpoints,
            # but provides robustness if endpoint extraction found nothing initially
            if not self.pending_endpoints and initial_response:
                logger.info("Re-extracting endpoints from initial response for manual crawl")
                initial_endpoints = self._extract_endpoints(initial_response)
                for endpoint in initial_endpoints:
                    if endpoint not in self.tested_endpoints:
                        self.pending_endpoints.add(endpoint)
                logger.info(
                    f"Populated {len(self.pending_endpoints)} endpoints for manual crawling"
                )

            # Only proceed with manual crawling if we have endpoints to crawl
            if self.pending_endpoints:
                self._manual_discovery_crawl()
            else:
                logger.warning(
                    "No endpoints available for manual crawling. "
                    "Discovery limited to root endpoint only."
                )

        # Final progress update
        self._update_progress(
            phase_progress=100.0,
            status_message=f"Discovery complete: {len(self.tested_endpoints)} endpoints, "
                          f"{len(self.discovered_forms)} forms"
        )

        logger.info(
            f"Discovery complete: {len(self.tested_endpoints)} endpoints visited, "
            f"{len(self.discovered_forms)} forms found, "
            f"{len(self.pending_endpoints)} endpoints remaining"
        )

    def _extract_forms_from_endpoints(self) -> None:
        """Extract forms from discovered endpoints after Katana scan.

        Visits a subset of Katana-discovered endpoints to extract forms
        and additional metadata for attack surface analysis.
        """
        # Calculate limit to avoid excessive requests
        form_extraction_limit = min(
            30,
            len(self.pending_endpoints),
            (self.max_requests - self.request_count) if self.max_requests else 30
        )

        if form_extraction_limit <= 0:
            logger.debug("No capacity for form extraction")
            return

        self._update_progress(
            status_message=f"Extracting forms from {form_extraction_limit} endpoints",
            phase_progress=60.0
        )

        processed = 0
        # Convert to list to avoid modifying set during iteration
        endpoints_to_visit = list(self.pending_endpoints)[:form_extraction_limit]

        for endpoint in endpoints_to_visit:
            if self.max_requests and self.request_count >= self.max_requests:
                logger.debug("Request limit reached during form extraction")
                break

            if endpoint in self.tested_endpoints:
                continue

            try:
                url = urljoin(self.target_url, endpoint)
                response = self._http_client.send_request(url=url, method="GET")
                self.request_count += 1
                processed += 1
                self.tested_endpoints.add(endpoint)
                self.pending_endpoints.discard(endpoint)

                # Extract forms from this page
                forms = self._extract_forms(response, endpoint)
                for form in forms:
                    if form not in self.discovered_forms:
                        self.discovered_forms.append(form)

                # Update progress every 5 endpoints
                if processed % 5 == 0:
                    progress = 60.0 + (processed / form_extraction_limit * 35.0)
                    self._update_progress(
                        total_endpoints_found=len(self.tested_endpoints) + len(self.pending_endpoints),
                        total_forms_found=len(self.discovered_forms),
                        phase_progress=progress,
                        status_message=f"Extracting forms: {processed}/{form_extraction_limit} endpoints"
                    )

            except HTTPClientError as e:
                logger.debug(f"Failed to extract forms from {endpoint}: {e}")

        logger.info(
            f"Form extraction complete: visited {processed} endpoints, "
            f"found {len(self.discovered_forms)} forms"
        )

    def _manual_discovery_crawl(self) -> None:
        """Perform manual breadth-first crawling for endpoint discovery.

        This is the fallback method when Katana is not available.
        Crawls pending endpoints, extracting forms and additional endpoints.
        """
        visited_in_discovery = 0
        max_discovery_requests = min(50, self.max_requests or 50)

        while self.pending_endpoints and visited_in_discovery < max_discovery_requests:
            if self.max_requests and self.request_count >= self.max_requests:
                break

            # Get next endpoint to crawl
            endpoint = self.pending_endpoints.pop()
            if endpoint in self.tested_endpoints:
                continue

            try:
                url = urljoin(self.target_url, endpoint)
                response = self._http_client.send_request(url=url, method="GET")
                self.request_count += 1
                visited_in_discovery += 1
                self.tested_endpoints.add(endpoint)

                # Extract forms from this page
                forms = self._extract_forms(response, endpoint)
                for form in forms:
                    if form not in self.discovered_forms:
                        self.discovered_forms.append(form)

                # Extract more endpoints
                new_endpoints = self._extract_endpoints(response)
                for ep in new_endpoints:
                    if ep not in self.tested_endpoints:
                        self.pending_endpoints.add(ep)

                # Update progress
                progress = min(
                    100.0,
                    30.0 + (visited_in_discovery / max_discovery_requests) * 65.0
                )
                self._update_progress(
                    total_endpoints_found=len(self.tested_endpoints) + len(self.pending_endpoints),
                    total_forms_found=len(self.discovered_forms),
                    phase_progress=progress,
                    status_message=f"Crawling: {endpoint}"
                )

            except HTTPClientError as e:
                logger.debug(f"Failed to crawl {endpoint}: {e}")

    def _analyze_katana_endpoints(self, endpoints: List[str]) -> Dict[str, Any]:
        """Analyze Katana-discovered endpoints using AI to categorize by risk.

        Sends endpoints to the LLM for security-focused categorization,
        identifying high-value targets for attack prioritization.

        Args:
            endpoints: List of endpoint URLs discovered by Katana.

        Returns:
            Dictionary with categorized endpoints by priority level.
        """
        import json

        if not endpoints:
            logger.debug("No endpoints to analyze")
            return {}

        # Select top endpoints to stay within token limits
        selected_endpoints = self._select_endpoints_for_analysis(endpoints)

        if not selected_endpoints:
            logger.debug("No high-value endpoints selected for analysis")
            return {}

        # Format endpoints for prompt
        endpoints_list = "\n".join(f"- {ep}" for ep in selected_endpoints)

        prompt = format_prompt(
            KATANA_RESULTS_ANALYSIS_PROMPT,
            target_url=self.target_url,
            endpoints_list=endpoints_list
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            logger.info(f"AI analyzing {len(selected_endpoints)} endpoints for categorization")
            response = self._ai_client.chat_with_retry(messages)

            # Parse the JSON response
            analysis_result = self._parse_katana_analysis_response(response)

            if analysis_result:
                high_count = len(analysis_result.get("high_priority", []))
                medium_count = len(analysis_result.get("medium_priority", []))
                low_count = len(analysis_result.get("low_priority", []))
                logger.info(
                    f"Katana analysis complete: {high_count} high, "
                    f"{medium_count} medium, {low_count} low priority endpoints"
                )

            return analysis_result

        except OllamaEngineError as e:
            logger.warning(f"Katana endpoint analysis failed: {e}")
            return {}

    def _select_endpoints_for_analysis(
        self, endpoints: List[str], max_endpoints: int = 100
    ) -> List[str]:
        """Select top endpoints for AI analysis based on security relevance.

        Scores endpoints by keywords suggesting security-sensitive functionality
        and returns the highest-scoring ones to stay within token limits.

        Args:
            endpoints: Full list of discovered endpoints.
            max_endpoints: Maximum number of endpoints to return.

        Returns:
            List of selected high-value endpoints.
        """
        # Scoring keywords - higher score = more interesting for security testing
        high_value_keywords = {
            # Authentication (score: 10)
            "login": 10, "signin": 10, "auth": 10, "logout": 10, "signout": 10,
            "register": 10, "signup": 10, "password": 10, "reset": 10, "forgot": 10,
            "session": 10, "token": 10, "oauth": 10, "sso": 10,
            # Admin/Management (score: 9)
            "admin": 9, "manage": 9, "dashboard": 9, "control": 9, "panel": 9,
            "config": 9, "settings": 9, "console": 9, "backend": 9,
            # File Operations (score: 8)
            "upload": 8, "download": 8, "file": 8, "document": 8, "import": 8,
            "export": 8, "attachment": 8, "media": 8,
            # API/Data (score: 7)
            "api": 7, "graphql": 7, "rest": 7, "json": 7, "xml": 7,
            "user": 7, "account": 7, "profile": 7,
            # Database/Query (score: 6)
            "search": 6, "query": 6, "filter": 6, "sort": 6, "list": 6,
            "id=": 6, "pid=": 6, "uid=": 6, "page=": 6,
            # Payment/Financial (score: 8)
            "payment": 8, "checkout": 8, "cart": 8, "order": 8, "billing": 8,
            "invoice": 8, "subscription": 8, "credit": 8,
        }

        # Low-value patterns to deprioritize
        low_value_patterns = [
            r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$",
            r"^/static/", r"^/assets/", r"^/images/", r"^/fonts/",
            r"^/node_modules/", r"^/vendor/",
        ]

        scored_endpoints: List[tuple] = []

        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            score = 0

            # Check for low-value patterns first
            is_low_value = False
            for pattern in low_value_patterns:
                if re.search(pattern, endpoint_lower):
                    is_low_value = True
                    break

            if is_low_value:
                score = -10  # Still include but at bottom
            else:
                # Score by keywords
                for keyword, keyword_score in high_value_keywords.items():
                    if keyword in endpoint_lower:
                        score += keyword_score

                # Bonus for endpoints with parameters
                if "?" in endpoint or "=" in endpoint:
                    score += 5

                # Bonus for dynamic-looking paths
                if re.search(r"/\d+(/|$|\?)", endpoint):
                    score += 3  # Likely ID in path

            scored_endpoints.append((score, endpoint))

        # Sort by score descending, take top N
        scored_endpoints.sort(key=lambda x: x[0], reverse=True)

        selected = [ep for score, ep in scored_endpoints[:max_endpoints]]

        logger.debug(
            f"Selected {len(selected)} of {len(endpoints)} endpoints for AI analysis"
        )

        return selected

    def _analysis_phase(self) -> None:
        """Phase 2: Have LLM analyze discovered elements and identify attack vectors.

        Sends all discovered forms, endpoints, and parameters to the LLM
        for analysis. The LLM identifies what attacks should be tried on each element.
        Integrates Katana endpoint analysis for enhanced prioritization.
        """
        import json

        # Build descriptions of discovered elements
        forms_desc = self._format_forms_for_analysis()
        params_desc = self._format_params_for_analysis()
        endpoints_desc = self._format_endpoints_for_analysis()

        # Enhance endpoints description with Katana high-priority insights
        katana_insights = self._format_katana_insights_for_analysis()
        if katana_insights:
            endpoints_desc = (endpoints_desc or "") + "\n\n" + katana_insights

        # Ask LLM to analyze and identify attack vectors
        prompt = format_prompt(
            ATTACK_VECTOR_ANALYSIS_PROMPT,
            target_url=self.target_url,
            detected_technology=self._format_technology_hints(),
            forms_description=forms_desc or "No forms discovered",
            url_params_description=params_desc or "No URL parameters discovered",
            endpoints_description=endpoints_desc or "No additional endpoints discovered"
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            self._update_progress(
                phase_progress=20.0,
                status_message="LLM analyzing discovered elements..."
            )

            response = self._ai_client.chat_with_retry(messages)

            # Parse the JSON response
            attack_vectors = self._parse_attack_vector_analysis(response)

            # Enrich attack vectors with Katana endpoint categories
            if self._katana_analysis_results:
                self._update_progress(
                    phase_progress=60.0,
                    status_message="Enriching vectors with Katana insights..."
                )
                attack_vectors = self._enrich_vectors_with_katana_categories(
                    attack_vectors
                )

            # Apply category-based priority boost
            attack_vectors = self._apply_category_priority_boost(attack_vectors)

            # Sort by priority (lower = higher priority)
            attack_vectors.sort(key=lambda x: x.priority)

            self.attack_vectors = attack_vectors
            self.progress.total_attack_vectors = len(attack_vectors)

            self._update_progress(
                phase_progress=100.0,
                status_message=f"Identified {len(attack_vectors)} attack vectors"
            )

            logger.info(
                f"Analysis complete: {len(attack_vectors)} attack vectors identified"
            )

            # Log summary of attack vectors with categories
            for av in attack_vectors[:5]:  # Log top 5
                category_info = f" [{av.endpoint_category}]" if av.endpoint_category else ""
                logger.info(
                    f"  [{av.priority}]{category_info} {av.element_type}:{av.element_name} -> "
                    f"{', '.join(av.suggested_attacks[:2])}"
                )
            if len(attack_vectors) > 5:
                logger.info(f"  ... and {len(attack_vectors) - 5} more")

        except OllamaEngineError as e:
            logger.error(f"Attack vector analysis failed: {e}")
            # Fall back to creating attack vectors from discovered forms
            self._create_fallback_attack_vectors()

    def _attack_phase(self) -> None:
        """Phase 3: Systematically attack each discovered vector.

        Works through the attack vector queue in priority order.
        For each vector, runs the suggested attacks until either:
        - A vulnerability is confirmed
        - All suggested attacks have been tested
        - Request limit is reached
        """
        total_vectors = len(self.attack_vectors)
        if total_vectors == 0:
            logger.warning("No attack vectors to test")
            return

        for idx, vector in enumerate(self.attack_vectors):
            # Check limits
            if self.max_requests and self.request_count >= self.max_requests:
                logger.info(f"Request limit reached during attack phase")
                vector.status = "skipped"
                continue

            # Update progress
            self.progress.attack_vectors_in_progress = 1
            self._update_progress(
                current_vector=f"{vector.element_type}:{vector.element_name}",
                status_message=f"Testing vector {idx+1}/{total_vectors}: {vector.element_name}"
            )

            vector.status = "testing"
            vector_found_vuln = False

            # Test each suggested attack type
            for attack_type in vector.suggested_attacks:
                if vector_found_vuln:
                    # Found a vuln, move to next vector
                    break

                if self.max_requests and self.request_count >= self.max_requests:
                    break

                self._update_progress(
                    current_attack_type=attack_type,
                    status_message=f"Testing {attack_type} on {vector.element_name}"
                )

                try:
                    # Execute attack against this vector
                    found = self._execute_smart_attack(vector, attack_type)

                    vector.tested_attacks.append(attack_type)

                    if found:
                        vector_found_vuln = True
                        vector.findings.append(attack_type)
                        # Mark confirmed so other vectors can skip redundant testing
                        self._confirmed_vulns.add((attack_type, vector.url))

                except Exception as e:
                    logger.error(f"Error testing {attack_type} on {vector.element_name}: {e}")

            # Mark vector complete
            vector.status = "completed"
            self.progress.attack_vectors_completed = idx + 1
            self.progress.attack_vectors_in_progress = 0
            self._update_progress()

            logger.info(
                f"Vector {idx+1}/{total_vectors} complete: {vector.element_name} "
                f"({'VULNERABLE' if vector_found_vuln else 'clean'})"
            )

    def _execute_smart_attack(
        self,
        vector: AttackVector,
        attack_type: str
    ) -> bool:
        """Execute a specific attack type against an attack vector.

        Uses LLM to generate targeted payloads for this specific
        vector and attack combination.

        Args:
            vector: The attack vector to test.
            attack_type: Type of attack to execute.

        Returns:
            True if vulnerability was found, False otherwise.
        """
        import json

        # Get form fields if this is a form-based vector
        form_fields_str = ""
        if vector.form_data:
            form_fields_str = "\n".join(
                f"  - {name}: {value or '(empty)'}"
                for name, value in vector.form_data.inputs.items()
            )

        # Ask LLM for targeted payloads
        prompt = format_prompt(
            SMART_ATTACK_PROMPT,
            url=vector.url,
            element_type=vector.element_type,
            element_name=vector.element_name,
            method=vector.method,
            element_context=vector.element_context,
            detected_technology=self._format_technology_hints(),
            attack_type=attack_type,
            form_fields=form_fields_str or "N/A (URL parameter attack)"
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            response = self._ai_client.chat_with_retry(messages)
            attack_plan = self._parse_smart_attack_response(response)

            payloads = attack_plan.get("payloads", [])
            if not payloads:
                logger.warning(f"No payloads generated for {attack_type}")
                return False

            # Execute each payload
            for payload_info in payloads:
                if self.max_requests and self.request_count >= self.max_requests:
                    break

                payload = payload_info.get("payload", "")
                inject_field = payload_info.get("inject_field", vector.element_name)

                if not payload:
                    continue

                # Execute the payload
                if vector.form_data:
                    # Form-based attack
                    finding = self._execute_form_payload(
                        vector, attack_type, payload, inject_field
                    )
                elif vector.element_type == "api_endpoint":
                    # API endpoint attack - use POST with JSON body
                    finding = self._execute_api_payload(
                        vector, attack_type, payload, inject_field
                    )
                else:
                    # URL parameter attack
                    finding = self._execute_url_payload(
                        vector, attack_type, payload
                    )

                if finding:
                    return True

            return False

        except OllamaEngineError as e:
            logger.error(f"Smart attack planning failed: {e}")
            # Fall back to generic payloads
            return self._execute_generic_attack(vector, attack_type)

    def _execute_form_payload(
        self,
        vector: AttackVector,
        attack_type: str,
        payload: str,
        inject_field: str
    ) -> bool:
        """Execute a payload against a form-based attack vector.

        Args:
            vector: Attack vector with form data.
            attack_type: Type of attack being tested.
            payload: The payload to inject.
            inject_field: Which form field to inject into.

        Returns:
            True if vulnerability indicator found.
        """
        if not vector.form_data:
            return False

        form = vector.form_data
        form_url = urljoin(self.target_url, form.action)

        # Build form data with payload
        form_data = {}
        for field_name, default_value in form.inputs.items():
            if field_name == inject_field or inject_field not in form.inputs:
                form_data[field_name] = payload
            else:
                form_data[field_name] = default_value or "test"

        try:
            if form.method.upper() == "POST":
                response = self._http_client.send_request(
                    url=form_url,
                    method="POST",
                    body=form_data,
                    form_data=True
                )
            else:
                # GET with query params
                from urllib.parse import urlencode
                query_string = urlencode(form_data)
                get_url = f"{form_url}?{query_string}"
                response = self._http_client.send_request(url=get_url, method="GET")

            self.request_count += 1

            # Track tested
            self.tested_endpoints.add(form.action)
            if attack_type not in self.tested_vectors:
                self.tested_vectors[attack_type] = []
            self.tested_vectors[attack_type].append(f"{inject_field}={payload[:30]}")

            # Analyze response
            context = (
                f"Testing {attack_type} on form field '{inject_field}' "
                f"at {form.action} with payload: {payload[:100]}"
            )
            analysis = self._analyze_response(response, context=context)

            # Check for vulnerability
            finding = self._check_for_vulnerability(analysis)

            if finding:
                # Record vulnerability using existing method
                self._parse_and_record_vulnerability(
                    analysis=analysis,
                    vuln_type=attack_type,
                    url=form_url,
                    method=form.method,
                    payload=f"{inject_field}={payload}",
                    response=response
                )
                logger.warning(
                    f"🎯 VULNERABILITY FOUND: {attack_type} in {inject_field}"
                )
                return True

            return False

        except HTTPClientError as e:
            logger.debug(f"Form payload test failed: {e}")
            return False

    def _execute_url_payload(
        self,
        vector: AttackVector,
        attack_type: str,
        payload: str
    ) -> bool:
        """Execute a payload against a URL parameter attack vector.

        Args:
            vector: Attack vector (URL-based).
            attack_type: Type of attack being tested.
            payload: The payload to inject.

        Returns:
            True if vulnerability indicator found.
        """
        try:
            # Build test URL
            base_url = vector.url
            if "?" in base_url:
                test_url = f"{base_url}&{vector.element_name}={payload}"
            else:
                test_url = f"{base_url}?{vector.element_name}={payload}"

            response = self._http_client.send_request(url=test_url, method="GET")
            self.request_count += 1

            # Track tested
            self.tested_endpoints.add(vector.endpoint)
            if attack_type not in self.tested_vectors:
                self.tested_vectors[attack_type] = []
            self.tested_vectors[attack_type].append(payload[:50])

            # Analyze
            context = (
                f"Testing {attack_type} on URL parameter '{vector.element_name}' "
                f"with payload: {payload[:100]}"
            )
            analysis = self._analyze_response(response, context=context)

            finding = self._check_for_vulnerability(analysis)

            if finding:
                # Record vulnerability using existing method
                self._parse_and_record_vulnerability(
                    analysis=analysis,
                    vuln_type=attack_type,
                    url=test_url,
                    method="GET",
                    payload=payload,
                    response=response
                )
                logger.warning(
                    f"🎯 VULNERABILITY FOUND: {attack_type} in URL param {vector.element_name}"
                )
                return True

            return False

        except HTTPClientError as e:
            logger.debug(f"URL payload test failed: {e}")
            return False

    def _execute_api_payload(
        self,
        vector: AttackVector,
        attack_type: str,
        payload: str,
        inject_field: str
    ) -> bool:
        """Execute a payload against an API endpoint attack vector.

        Sends payloads in JSON body for REST API endpoints.
        Also tests SQL injection in URL path segments.

        Args:
            vector: Attack vector (API endpoint).
            attack_type: Type of attack being tested.
            payload: The payload to inject.
            inject_field: Field name to inject into (for JSON body).

        Returns:
            True if vulnerability indicator found.
        """
        import json as json_lib

        findings = []

        try:
            # Method 1: POST request with JSON body containing payload
            if vector.method.upper() in ("POST", "PUT", "PATCH"):
                json_body = {inject_field: payload}

                # Also add common fields that APIs might expect
                if "user" in vector.endpoint.lower() or "login" in vector.endpoint.lower():
                    json_body.update({
                        "email": payload if "email" in inject_field.lower() else "test@test.com",
                        "password": payload if "pass" in inject_field.lower() else "test123"
                    })

                response = self._http_client.send_request(
                    url=vector.url,
                    method=vector.method.upper(),
                    body=json_body,
                    headers={"Content-Type": "application/json"}
                )
                self.request_count += 1

                # Analyze the response
                context = (
                    f"Testing {attack_type} on API endpoint '{vector.endpoint}' "
                    f"via {vector.method} with JSON payload: {json_lib.dumps(json_body)[:200]}"
                )
                analysis = self._analyze_response(response, context=context)

                if self._check_for_vulnerability(analysis):
                    self._parse_and_record_vulnerability(
                        analysis=analysis,
                        vuln_type=attack_type,
                        url=vector.url,
                        method=vector.method,
                        payload=json_lib.dumps(json_body),
                        response=response
                    )
                    logger.warning(
                        f"🎯 VULNERABILITY FOUND: {attack_type} in API {vector.endpoint}"
                    )
                    return True

            # Method 2: GET request with payload in query parameter
            test_url = vector.url
            if "?" in test_url:
                test_url = f"{test_url}&{inject_field}={payload}"
            else:
                test_url = f"{test_url}?{inject_field}={payload}"

            response = self._http_client.send_request(url=test_url, method="GET")
            self.request_count += 1

            context = (
                f"Testing {attack_type} on API endpoint '{vector.endpoint}' "
                f"via GET with query param: {inject_field}={payload[:100]}"
            )
            analysis = self._analyze_response(response, context=context)

            if self._check_for_vulnerability(analysis):
                self._parse_and_record_vulnerability(
                    analysis=analysis,
                    vuln_type=attack_type,
                    url=test_url,
                    method="GET",
                    payload=f"{inject_field}={payload}",
                    response=response
                )
                logger.warning(
                    f"🎯 VULNERABILITY FOUND: {attack_type} in API query param {vector.endpoint}"
                )
                return True

            # Track tested
            self.tested_endpoints.add(vector.endpoint)
            if attack_type not in self.tested_vectors:
                self.tested_vectors[attack_type] = []
            self.tested_vectors[attack_type].append(payload[:50])

            return False

        except HTTPClientError as e:
            logger.debug(f"API payload test failed: {e}")
            return False

    def _execute_generic_attack(
        self,
        vector: AttackVector,
        attack_type: str
    ) -> bool:
        """Fallback: Execute generic payloads when LLM fails.

        Args:
            vector: Attack vector to test.
            attack_type: Type of attack.

        Returns:
            True if vulnerability found.
        """
        # Generate payloads using existing method
        payloads = self._generate_payloads(attack_type)

        if not payloads:
            return False

        for payload_info in payloads[:3]:  # Limit to 3 generic payloads
            if self.max_requests and self.request_count >= self.max_requests:
                break

            payload = payload_info.get("payload", "")
            if not payload:
                continue

            if vector.form_data:
                finding = self._execute_form_payload(
                    vector, attack_type, payload, vector.element_name
                )
            else:
                finding = self._execute_url_payload(
                    vector, attack_type, payload
                )

            if finding:
                return True

        return False

    # =========================================================================
    # HELPER METHODS FOR NEW PHASES
    # =========================================================================

    def _format_forms_for_analysis(self) -> str:
        """Format discovered forms for LLM analysis."""
        if not self.discovered_forms:
            return ""

        lines = []
        for i, form in enumerate(self.discovered_forms, 1):
            fields = ", ".join(
                f"{name}={value or '(empty)'}"
                for name, value in form.inputs.items()
            )
            lines.append(
                f"{i}. Form at {form.action} (method={form.method})\n"
                f"   Fields: {fields}\n"
                f"   Found on: {form.endpoint}"
            )
        return "\n".join(lines)

    def _format_params_for_analysis(self) -> str:
        """Format discovered URL parameters for LLM analysis."""
        if not self.discovered_params:
            return ""

        lines = []
        for endpoint, params in self.discovered_params.items():
            lines.append(f"- {endpoint}: {', '.join(params)}")
        return "\n".join(lines)

    def _format_endpoints_for_analysis(self) -> str:
        """Format discovered endpoints for LLM analysis."""
        endpoints = list(self.tested_endpoints) + list(self.pending_endpoints)
        if not endpoints:
            return ""

        # Group by type/pattern
        return "\n".join(f"- {ep}" for ep in sorted(endpoints)[:30])

    def _parse_attack_vector_analysis(self, response: str) -> List[AttackVector]:
        """Parse LLM response into AttackVector objects.

        Args:
            response: LLM response (expected to contain JSON).

        Returns:
            List of AttackVector objects.
        """
        import json

        vectors = []

        # Try to extract JSON from response
        json_match = re.search(r'\[[\s\S]*\]', response)
        if not json_match:
            logger.warning("No JSON array found in attack vector analysis")
            return self._create_fallback_attack_vectors()

        # Try parsing the matched JSON, with fallback for malformed responses
        json_str = json_match.group()
        data = None

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            # Try to find and parse just the first complete JSON array
            # by finding matching brackets
            logger.debug(f"Initial JSON parse failed: {e}, trying bracket matching")
            bracket_count = 0
            start_idx = json_str.find('[')
            if start_idx != -1:
                for i, char in enumerate(json_str[start_idx:], start_idx):
                    if char == '[':
                        bracket_count += 1
                    elif char == ']':
                        bracket_count -= 1
                        if bracket_count == 0:
                            # Found the complete first array
                            try:
                                data = json.loads(json_str[start_idx:i+1])
                                logger.info(f"Successfully parsed JSON array with bracket matching")
                                break
                            except json.JSONDecodeError:
                                pass

        if data is None:
            logger.warning("Failed to parse attack vector JSON after all attempts")
            return self._create_fallback_attack_vectors()

        try:

            for item in data:
                # Find associated form if this is form-based
                form_data = None
                if item.get("element_type") == "form":
                    for form in self.discovered_forms:
                        if (form.action == item.get("url") or
                            item.get("element_name") in form.inputs):
                            form_data = form
                            break

                vector = AttackVector(
                    id=self._generate_attack_vector_id(),
                    url=item.get("url", self.target_url),
                    endpoint=item.get("url", "/").split("?")[0],
                    method=item.get("method", "GET"),
                    element_type=item.get("element_type", "unknown"),
                    element_name=item.get("element_name", "unknown"),
                    element_context=item.get("context", ""),
                    suggested_attacks=item.get("suggested_attacks", []),
                    priority=item.get("priority", 3),
                    form_data=form_data,
                )
                vectors.append(vector)

            return vectors

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse attack vector JSON: {e}")
            return self._create_fallback_attack_vectors()

    def _create_fallback_attack_vectors(self) -> List[AttackVector]:
        """Create attack vectors from discovered forms and Katana endpoints when LLM analysis fails."""
        vectors = []

        # Create vectors for each form field
        for form in self.discovered_forms:
            for field_name in form.inputs.keys():
                # Skip obvious non-injectable fields
                if field_name.lower() in ("submit", "button", "csrf", "token"):
                    continue

                # Determine likely attacks based on field name
                suggested = []
                name_lower = field_name.lower()

                if any(x in name_lower for x in ("user", "name", "login", "email")):
                    suggested = ["SQL Injection", "XSS", "Authentication Bypass"]
                elif any(x in name_lower for x in ("pass", "pwd", "secret")):
                    suggested = ["SQL Injection", "Authentication Bypass"]
                elif any(x in name_lower for x in ("search", "query", "q", "s")):
                    suggested = ["SQL Injection", "XSS", "Command Injection"]
                elif any(x in name_lower for x in ("id", "num", "no")):
                    suggested = ["SQL Injection", "Broken Access Control"]
                elif any(x in name_lower for x in ("file", "path", "dir")):
                    suggested = ["Path Traversal", "Command Injection"]
                elif any(x in name_lower for x in ("url", "link", "redirect")):
                    suggested = ["SSRF", "Open Redirect"]
                else:
                    suggested = ["XSS", "SQL Injection"]

                vector = AttackVector(
                    id=self._generate_attack_vector_id(),
                    url=urljoin(self.target_url, form.action),
                    endpoint=form.action,
                    method=form.method,
                    element_type="form_field",
                    element_name=field_name,
                    element_context=f"Form field in {form.action}",
                    suggested_attacks=suggested,
                    priority=1 if "login" in form.action.lower() else 2,
                    form_data=form,
                )
                vectors.append(vector)

        # If no forms, create vectors from Katana high-priority endpoints
        if not vectors and self._katana_analysis_results:
            high_priority = self._katana_analysis_results.get("high_priority", [])
            medium_priority = self._katana_analysis_results.get("medium_priority", [])

            # Combine high and medium priority endpoints
            priority_endpoints = high_priority + medium_priority[:5]

            for item in priority_endpoints:
                endpoint = item.get("endpoint", "")
                if not endpoint:
                    continue

                # Determine attacks based on endpoint pattern
                suggested = item.get("suggested_attacks", [])
                if not suggested:
                    endpoint_lower = endpoint.lower()
                    if any(x in endpoint_lower for x in ("login", "auth", "user")):
                        suggested = ["SQL Injection", "Authentication Bypass", "XSS"]
                    elif any(x in endpoint_lower for x in ("api", "rest")):
                        suggested = ["SQL Injection", "Broken Access Control", "API Security"]
                    elif any(x in endpoint_lower for x in ("search", "query")):
                        suggested = ["SQL Injection", "XSS"]
                    elif any(x in endpoint_lower for x in ("file", "upload", "download")):
                        suggested = ["Path Traversal", "File Upload Vulnerability"]
                    elif any(x in endpoint_lower for x in ("redirect", "url", "link")):
                        suggested = ["Open Redirect", "SSRF"]
                    else:
                        suggested = ["SQL Injection", "XSS", "Broken Access Control"]

                # Determine method - POST for auth/create endpoints, GET otherwise
                method = "POST" if any(x in endpoint.lower() for x in ("login", "create", "register", "add")) else "GET"

                vector = AttackVector(
                    id=self._generate_attack_vector_id(),
                    url=urljoin(self.target_url, endpoint),
                    endpoint=endpoint,
                    method=method,
                    element_type="api_endpoint",
                    element_name=endpoint.split("/")[-1] or "endpoint",
                    element_context=f"Katana-discovered endpoint: {item.get('category', 'unknown')}",
                    suggested_attacks=suggested,
                    priority=1 if item in high_priority else 2,
                    form_data=None,
                )
                vectors.append(vector)

        logger.info(f"Created {len(vectors)} fallback attack vectors")
        return vectors

    def _format_katana_insights_for_analysis(self) -> str:
        """Format Katana analysis insights for inclusion in attack vector analysis.

        Returns:
            Formatted string with high-priority endpoint insights.
        """
        if not self._katana_analysis_results:
            return ""

        high_priority = self._katana_analysis_results.get("high_priority", [])
        if not high_priority:
            return ""

        lines = ["## High-Priority Endpoints (from AI-categorized Katana results):"]
        for item in high_priority[:10]:  # Limit to top 10
            endpoint = item.get("endpoint", "")
            category = item.get("category", "Unknown")
            reasoning = item.get("reasoning", "")
            suggested = item.get("suggested_attacks", [])
            lines.append(
                f"- **{endpoint}** [{category}]: {reasoning}"
            )
            if suggested:
                lines.append(f"  Suggested: {', '.join(suggested[:3])}")

        return "\n".join(lines)

    def _enrich_vectors_with_katana_categories(
        self, vectors: List[AttackVector]
    ) -> List[AttackVector]:
        """Enrich attack vectors with endpoint categories from Katana analysis.

        Matches attack vectors to categorized Katana endpoints and sets
        the endpoint_category field. Also adds Katana-suggested attacks.

        Args:
            vectors: List of attack vectors to enrich.

        Returns:
            Enriched attack vectors.
        """
        if not self._katana_analysis_results:
            return vectors

        # Build endpoint-to-category lookup from all priority levels
        endpoint_lookup: Dict[str, Dict[str, Any]] = {}

        for priority_level in ["high_priority", "medium_priority", "low_priority"]:
            for item in self._katana_analysis_results.get(priority_level, []):
                endpoint = item.get("endpoint", "")
                if endpoint:
                    endpoint_lookup[endpoint] = {
                        "category": item.get("category", "Unknown"),
                        "suggested_attacks": item.get("suggested_attacks", []),
                        "priority_level": priority_level,
                    }

        # Match vectors to Katana endpoints
        enriched_count = 0
        for vector in vectors:
            # Try exact match first
            matched_info = None
            if vector.endpoint in endpoint_lookup:
                matched_info = endpoint_lookup[vector.endpoint]
            elif vector.url in endpoint_lookup:
                matched_info = endpoint_lookup[vector.url]
            else:
                # Try partial match - check if vector endpoint is in any Katana endpoint
                for ep, info in endpoint_lookup.items():
                    # Match on path component
                    vector_path = vector.endpoint.split("?")[0]
                    ep_path = ep.split("?")[0]
                    if vector_path == ep_path or vector_path in ep or ep_path in vector_path:
                        matched_info = info
                        break

            if matched_info:
                vector.endpoint_category = matched_info["category"]
                vector.katana_priority_level = matched_info.get("priority_level")
                enriched_count += 1

                # Add Katana-suggested attacks that aren't already present
                for attack in matched_info.get("suggested_attacks", []):
                    if attack not in vector.suggested_attacks:
                        vector.suggested_attacks.append(attack)

        logger.info(
            f"Enriched {enriched_count}/{len(vectors)} attack vectors with "
            f"Katana endpoint categories"
        )

        return vectors

    def _apply_category_priority_boost(
        self, vectors: List[AttackVector]
    ) -> List[AttackVector]:
        """Apply priority adjustments based on endpoint category and Katana priority level.

        Boosts priority (lower number) for high-risk categories and
        penalizes low-risk categories. Also adjusts based on AI-assessed
        Katana priority levels so high-risk endpoints are tested first.

        Args:
            vectors: List of attack vectors to adjust.

        Returns:
            Vectors with adjusted priorities.
        """
        # Priority boost mapping (negative = higher priority, positive = lower priority)
        category_boost = {
            "Authentication": -2,      # Critical - boost priority
            "Admin Panel": -2,         # Critical - boost priority
            "File Operation": -1,      # High risk - boost
            "Payment/Financial": -1,   # High risk - boost
            "API Endpoint": 0,         # Neutral
            "Database Query": 0,       # Neutral
            "User Profile": 0,         # Neutral
            "Static Resource": 2,      # Low risk - deprioritize
            "Unknown": 0,              # Neutral
        }

        # Katana priority level adjustments (negative = higher priority)
        priority_level_boost = {
            "high_priority": -1,    # AI-assessed high-risk - boost priority
            "medium_priority": 0,   # Neutral
            "low_priority": 1,      # AI-assessed low-risk - deprioritize
        }

        for vector in vectors:
            original_priority = vector.priority
            total_boost = 0

            # Apply category-based boost
            if vector.endpoint_category:
                total_boost += category_boost.get(vector.endpoint_category, 0)

            # Apply Katana priority level boost
            if vector.katana_priority_level:
                total_boost += priority_level_boost.get(
                    vector.katana_priority_level, 0
                )

            # Apply combined boost and clamp to 1-5
            if total_boost != 0:
                new_priority = max(1, min(5, vector.priority + total_boost))
                if new_priority != original_priority:
                    logger.debug(
                        f"Adjusted priority for {vector.element_name}: "
                        f"{original_priority} -> {new_priority} "
                        f"(category: {vector.endpoint_category}, "
                        f"katana_level: {vector.katana_priority_level})"
                    )
                    vector.priority = new_priority

        return vectors

    def _parse_smart_attack_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM smart attack response.

        Args:
            response: LLM response with attack plan.

        Returns:
            Dictionary with payloads and attack completion criteria.
        """
        import json

        # Try to extract JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # Fall back to parsing payload lines
        payloads = []
        for line in response.split("\n"):
            if "payload" in line.lower() and ":" in line:
                payload = line.split(":", 1)[1].strip().strip('"\'')
                if payload:
                    payloads.append({"payload": payload, "inject_field": ""})

        return {"payloads": payloads}

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

        Uses multiple detection strategies:
        1. Positive indicators that suggest vulnerability
        2. Negative indicators that suggest no vulnerability
        3. Technical evidence patterns

        Args:
            analysis: AI analysis text.

        Returns:
            True if vulnerability indicators are present.
        """
        analysis_lower = analysis.lower()

        # Strong negative indicators - if present, likely NOT vulnerable
        negative_indicators = [
            "no vulnerability",
            "not vulnerable",
            "no security issue",
            "appears safe",
            "properly sanitized",
            "properly escaped",
            "no evidence of",
            "low confidence",
            "severity: none",
            "no findings",
        ]

        # Check for explicit negative indicators first
        for neg in negative_indicators:
            if neg in analysis_lower:
                # But check if it's negated (e.g., "not properly sanitized")
                neg_idx = analysis_lower.find(neg)
                prefix = analysis_lower[max(0, neg_idx-10):neg_idx]
                if "not" not in prefix and "no" not in prefix:
                    return False

        # Strong positive indicators
        positive_indicators = [
            "vulnerability found",
            "vulnerability detected",
            "vulnerable",
            "security issue",
            "security vulnerability",
            "high confidence",
            "confirmed vulnerability",
            "exploitable",
            "severity: critical",
            "severity: high",
            "severity: medium",
            "sql injection",
            "xss",
            "cross-site scripting",
            "command injection",
            "path traversal",
            "directory traversal",
            "authentication bypass",
            "broken access control",
            "information disclosure",
            "sensitive data exposure",
            "error message reveals",
            "stack trace",
            "database error",
            "syntax error",
            "sql error",
        ]

        # Check for positive indicators
        for pos in positive_indicators:
            if pos in analysis_lower:
                return True

        # Technical evidence patterns (SQL injection indicators in response)
        sql_error_patterns = [
            "mysql",
            "sqlite",
            "postgresql",
            "ora-",
            "sql server",
            "syntax error",
            "unclosed quotation",
            "unterminated string",
        ]

        for pattern in sql_error_patterns:
            if pattern in analysis_lower:
                return True

        return False

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

    def _parse_katana_analysis_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response from Katana endpoint analysis.

        Extracts JSON from the response, handling markdown code blocks
        and validating the expected structure.

        Args:
            response: LLM response text (may contain markdown).

        Returns:
            Dictionary with high_priority, medium_priority, low_priority lists.
        """
        import json

        # Try to extract JSON from markdown code block first
        json_block_match = re.search(
            r'```(?:json)?\s*([\s\S]*?)```', response
        )

        if json_block_match:
            json_str = json_block_match.group(1).strip()
        else:
            # Try to find raw JSON object
            json_obj_match = re.search(r'\{[\s\S]*\}', response)
            if json_obj_match:
                json_str = json_obj_match.group()
            else:
                logger.warning("No JSON found in Katana analysis response")
                return {}

        try:
            data = json.loads(json_str)

            # Validate expected structure
            result = {
                "high_priority": data.get("high_priority", []),
                "medium_priority": data.get("medium_priority", []),
                "low_priority": data.get("low_priority", []),
                "summary": data.get("summary", {}),
            }

            # Validate each endpoint entry has required fields
            for priority_level in ["high_priority", "medium_priority", "low_priority"]:
                validated_endpoints = []
                for item in result[priority_level]:
                    if isinstance(item, dict) and "endpoint" in item:
                        validated_endpoints.append({
                            "endpoint": item.get("endpoint", ""),
                            "category": item.get("category", "Unknown"),
                            "reasoning": item.get("reasoning", ""),
                            "suggested_attacks": item.get("suggested_attacks", []),
                        })
                result[priority_level] = validated_endpoints

            return result

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Katana analysis JSON: {e}")
            return {}

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

