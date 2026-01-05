"""Markdown report generation for AI DAST scan results.

This module provides functions to generate professional security scan reports
in Markdown format from DASTScanner scan results.

Main Functions:
    - generate_report: Creates a complete Markdown report from scan results
    - save_report: Saves the report to a timestamped file

Example:
    >>> from scanner.scanner import DASTScanner
    >>> from scanner.report_generator import generate_report, save_report
    >>> scanner = DASTScanner("http://localhost:8080")
    >>> results = scanner.scan()
    >>> report = generate_report(results)
    >>> filepath = save_report(report, output_dir="reports")
    >>> print(f"Report saved to: {filepath}")
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Severity ordering for consistent report structure
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# Visual indicators for severity levels
SEVERITY_ICONS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Informational": "⚪",
}


def _format_duration(seconds: float) -> str:
    """Convert seconds to human-readable format.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted string (e.g., "2m 30s", "1h 15m 30s").
    """
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"

    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins}m {secs}s"


def _calculate_risk_level(vulnerabilities: List[Dict]) -> str:
    """Determine overall risk level based on vulnerability severities.

    Args:
        vulnerabilities: List of vulnerability dictionaries.

    Returns:
        Risk level string (Critical/High/Medium/Low/None).
    """
    if not vulnerabilities:
        return "None"

    severities = {v.get("severity", "").lower() for v in vulnerabilities}

    if "critical" in severities:
        return "Critical"
    if "high" in severities:
        return "High"
    if "medium" in severities:
        return "Medium"
    if "low" in severities:
        return "Low"
    return "Informational"


def _group_by_severity(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """Group vulnerabilities by severity level.

    Args:
        vulnerabilities: List of vulnerability dictionaries.

    Returns:
        Dictionary with severity as key and list of vulnerabilities as value.
    """
    grouped: Dict[str, List[Dict]] = {severity: [] for severity in SEVERITY_ORDER}

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Informational")
        if severity in grouped:
            grouped[severity].append(vuln)
        else:
            grouped["Informational"].append(vuln)

    return grouped


def _truncate_text(text: str, max_length: int = 500) -> str:
    """Truncate long text for display in report.

    Args:
        text: Text to truncate.
        max_length: Maximum length before truncation.

    Returns:
        Truncated text with indicator if shortened.
    """
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "... [truncated]"


def _generate_executive_summary(scan_results: Dict[str, Any]) -> str:
    """Generate the executive summary section of the report.

    Args:
        scan_results: Complete scan results dictionary.

    Returns:
        Markdown string for executive summary section.
    """
    target_url = scan_results.get("target_url", "Unknown")
    stats = scan_results.get("statistics", {})
    vulnerabilities = scan_results.get("vulnerabilities", [])

    duration = stats.get("duration_seconds", 0)
    requests = stats.get("total_requests", 0)
    endpoints = stats.get("unique_endpoints_tested", 0)
    status = stats.get("status", "unknown")
    scan_start = stats.get("scan_start", "N/A")

    # Count by severity
    grouped = _group_by_severity(vulnerabilities)
    total_vulns = len(vulnerabilities)
    risk_level = _calculate_risk_level(vulnerabilities)

    # Format timestamp
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# 🛡️ Security Scan Report",
        "",
        f"**Target:** `{target_url}`  ",
        f"**Report Generated:** {report_time}  ",
        f"**Scan Status:** {status.title()}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "### Scan Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Target URL | `{target_url}` |",
        f"| Scan Duration | {_format_duration(duration)} |",
        f"| Total Requests | {requests} |",
        f"| Endpoints Tested | {endpoints} |",
        f"| Vulnerabilities Found | {total_vulns} |",
        f"| Scan Start | {scan_start} |",
        "",
        "### Risk Assessment",
        "",
        f"**Overall Risk Level: {SEVERITY_ICONS.get(risk_level, '⚪')} {risk_level}**",
        "",
        "### Vulnerability Breakdown",
        "",
        "| Severity | Count | Percentage |",
        "|----------|-------|------------|",
    ]

    for severity in SEVERITY_ORDER:
        count = len(grouped.get(severity, []))
        percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
        icon = SEVERITY_ICONS.get(severity, "⚪")
        lines.append(f"| {icon} {severity} | {count} | {percentage:.1f}% |")

    lines.append("")

    # Add error information if present
    if scan_results.get("error"):
        lines.extend([
            "### ⚠️ Scan Error",
            "",
            f"The scan encountered an error: `{scan_results['error']}`",
            "",
        ])

    return "\n".join(lines)


def _generate_vulnerability_findings(scan_results: Dict[str, Any]) -> str:
    """Generate detailed vulnerability findings section.

    Args:
        scan_results: Complete scan results dictionary.

    Returns:
        Markdown string for vulnerability findings section.
    """
    vulnerabilities = scan_results.get("vulnerabilities", [])

    if not vulnerabilities:
        return "\n## Vulnerability Findings\n\n✅ **No vulnerabilities were detected during this scan.**\n"

    lines = [
        "",
        "## Vulnerability Findings",
        "",
    ]

    grouped = _group_by_severity(vulnerabilities)

    for severity in SEVERITY_ORDER:
        vulns = grouped.get(severity, [])
        if not vulns:
            continue

        icon = SEVERITY_ICONS.get(severity, "⚪")
        lines.extend([
            f"### {icon} {severity} Severity ({len(vulns)} found)",
            "",
        ])

        for idx, vuln in enumerate(vulns, 1):
            vuln_type = vuln.get("type", "Unknown Vulnerability")
            confidence = vuln.get("confidence", "Unknown")
            url = vuln.get("url", "N/A")
            method = vuln.get("method", "N/A")
            payload = vuln.get("payload")
            evidence = vuln.get("evidence", "")
            exploitation = vuln.get("exploitation_steps")
            recommendation = vuln.get("recommendation")

            lines.extend([
                f"#### {idx}. {vuln_type}",
                "",
                f"- **Confidence:** {confidence}",
                f"- **URL:** `{url}`",
                f"- **Method:** {method}",
            ])

            if payload:
                lines.extend([
                    f"- **Payload:**",
                    "  ```",
                    f"  {payload}",
                    "  ```",
                ])

            if evidence:
                truncated_evidence = _truncate_text(evidence, 1000)
                lines.extend([
                    "",
                    "<details>",
                    "<summary>📋 Evidence (click to expand)</summary>",
                    "",
                    "```",
                    truncated_evidence,
                    "```",
                    "",
                    "</details>",
                ])

            if exploitation:
                lines.extend([
                    "",
                    f"**🔓 Exploitation Steps:** {exploitation}",
                ])

            if recommendation:
                lines.extend([
                    "",
                    f"**🔧 Recommendation:** {recommendation}",
                ])

            lines.append("")

    return "\n".join(lines)


def _generate_recommendations(scan_results: Dict[str, Any]) -> str:
    """Generate aggregated recommendations section.

    Args:
        scan_results: Complete scan results dictionary.

    Returns:
        Markdown string for recommendations section.
    """
    vulnerabilities = scan_results.get("vulnerabilities", [])

    if not vulnerabilities:
        return ""

    # Collect unique recommendations grouped by vulnerability type
    recommendations_by_type: Dict[str, Dict[str, Any]] = {}

    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "Unknown")
        recommendation = vuln.get("recommendation")
        severity = vuln.get("severity", "Informational")

        if recommendation and vuln_type not in recommendations_by_type:
            recommendations_by_type[vuln_type] = {
                "recommendation": recommendation,
                "severity": severity,
            }

    if not recommendations_by_type:
        return ""

    lines = [
        "",
        "## Remediation Recommendations",
        "",
        "The following recommendations are prioritized by severity:",
        "",
    ]

    # Sort by severity
    severity_priority = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_types = sorted(
        recommendations_by_type.items(),
        key=lambda x: severity_priority.get(x[1]["severity"], 99)
    )

    for idx, (vuln_type, data) in enumerate(sorted_types, 1):
        icon = SEVERITY_ICONS.get(data["severity"], "⚪")
        lines.extend([
            f"{idx}. {icon} **{vuln_type}**",
            f"   - {data['recommendation']}",
            "",
        ])

    # Add general security best practices
    lines.extend([
        "### 📚 General Security Best Practices",
        "",
        "- Keep all software and dependencies up to date",
        "- Implement input validation and output encoding",
        "- Use parameterized queries for database operations",
        "- Implement proper authentication and session management",
        "- Apply the principle of least privilege",
        "- Enable security headers (CSP, X-Frame-Options, etc.)",
        "- Conduct regular security assessments",
        "",
        "### 🔗 Useful Resources",
        "",
        "- [OWASP Top 10](https://owasp.org/www-project-top-ten/)",
        "- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)",
        "- [CWE Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)",
        "",
    ])

    return "\n".join(lines)


def _generate_scan_metadata(scan_results: Dict[str, Any]) -> str:
    """Generate scan metadata and technical details section.

    Args:
        scan_results: Complete scan results dictionary.

    Returns:
        Markdown string for scan metadata section.
    """
    model_info = scan_results.get("model_info", {})
    tested_vectors = scan_results.get("tested_vectors", {})
    technology_hints = scan_results.get("technology_hints", [])
    stats = scan_results.get("statistics", {})

    lines = [
        "",
        "## Scan Details",
        "",
        "### 🤖 AI Model Information",
        "",
        "| Property | Value |",
        "|----------|-------|",
        f"| Model | {model_info.get('model', 'N/A')} |",
        f"| Host | {model_info.get('host', 'N/A')} |",
        "",
    ]

    # Tested attack vectors
    if tested_vectors:
        lines.extend([
            "### 🎯 Tested Attack Vectors",
            "",
            "| Category | Payloads Tested |",
            "|----------|-----------------|",
        ])

        for category, payloads in tested_vectors.items():
            lines.append(f"| {category} | {len(payloads)} |")

        lines.append("")

    # Detected technologies
    if technology_hints:
        lines.extend([
            "### 🔍 Detected Technologies",
            "",
        ])

        if isinstance(technology_hints, dict):
            for key, value in technology_hints.items():
                lines.append(f"- {key}: {value}")
        else:
            for tech in technology_hints:
                lines.append(f"- {tech}")

        lines.append("")

    # Scan statistics
    lines.extend([
        "### 📊 Scan Statistics",
        "",
        "| Statistic | Value |",
        "|-----------|-------|",
        f"| Total Requests | {stats.get('total_requests', 0)} |",
        f"| Unique Endpoints | {stats.get('unique_endpoints_tested', 0)} |",
        f"| Duration | {_format_duration(stats.get('duration_seconds', 0))} |",
        f"| Status | {stats.get('status', 'N/A')} |",
        "",
    ])

    return "\n".join(lines)


def generate_report(scan_results: Dict[str, Any]) -> str:
    """Generate a complete Markdown security scan report.

    This function takes scan results from DASTScanner and generates a
    professional Markdown report with executive summary, detailed findings,
    recommendations, and scan metadata.

    Args:
        scan_results: Complete scan results dictionary from DASTScanner.get_scan_results().
            Expected keys:
            - target_url: The scanned URL
            - vulnerabilities: List of vulnerability dictionaries
            - statistics: Scan statistics (requests, duration, etc.)
            - model_info: AI model information
            - tested_vectors: Dictionary of tested attack categories
            - technology_hints: List of detected technologies

    Returns:
        Complete Markdown report as a string.

    Raises:
        ValueError: If scan_results is not a valid dictionary.

    Example:
        >>> from scanner.scanner import DASTScanner
        >>> from scanner.report_generator import generate_report
        >>> scanner = DASTScanner("http://localhost:8080")
        >>> results = scanner.scan()
        >>> report = generate_report(results)
        >>> print(report)
    """
    if not isinstance(scan_results, dict):
        raise ValueError("scan_results must be a dictionary")

    # Generate all sections
    sections = [
        _generate_executive_summary(scan_results),
        _generate_vulnerability_findings(scan_results),
        _generate_recommendations(scan_results),
        _generate_scan_metadata(scan_results),
    ]

    # Add footer
    footer_lines = [
        "",
        "---",
        "",
        f"*Report generated by AI DAST Scanner on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}*",
        "",
    ]
    sections.append("\n".join(footer_lines))

    return "\n".join(sections)


def save_report(
    report_content: str,
    output_dir: str = "reports",
    filename: Optional[str] = None,
) -> str:
    """Save the generated report to a file.

    Creates the output directory if it doesn't exist and saves the report
    with a timestamped filename.

    Args:
        report_content: The Markdown report content to save.
        output_dir: Directory to save the report (default: "reports").
        filename: Optional custom filename. If not provided, generates a
            timestamped filename like "dast_report_20240115_143022.md".

    Returns:
        Absolute path to the saved report file.

    Raises:
        OSError: If unable to create directory or write file.

    Example:
        >>> report = generate_report(scan_results)
        >>> filepath = save_report(report, output_dir="reports")
        >>> print(f"Report saved to: {filepath}")
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create output directory: {e}")
        raise

    # Generate filename if not provided
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dast_report_{timestamp}.md"

    # Ensure filename has .md extension
    if not filename.endswith(".md"):
        filename += ".md"

    # Write report to file
    file_path = output_path / filename
    try:
        file_path.write_text(report_content, encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to write report file: {e}")
        raise

    absolute_path = str(file_path.resolve())
    logger.info(f"Report saved to: {absolute_path}")

    return absolute_path