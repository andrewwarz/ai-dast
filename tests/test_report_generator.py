"""Unit tests for the Report Generator module.

This module tests:
- Report generation with various scan results
- File operations for saving reports
- Helper functions for formatting and calculations
"""

import os
import tempfile
from pathlib import Path

import pytest

from scanner.report_generator import (
    generate_report,
    save_report,
    _format_duration,
    _calculate_risk_level,
    _group_by_severity,
    _generate_executive_summary,
    _generate_vulnerability_findings,
    _generate_recommendations,
    _generate_scan_metadata,
    SEVERITY_ORDER,
    SEVERITY_ICONS,
)


# =============================================================================
# HELPER FUNCTION TESTS
# =============================================================================

class TestHelperFunctions:
    """Tests for report generator helper functions."""

    def test_format_duration_seconds(self):
        """Test duration formatting for seconds only."""
        assert _format_duration(5.5) == "5.5s"
        assert _format_duration(0.1) == "0.1s"
        assert _format_duration(59.9) == "59.9s"

    def test_format_duration_minutes(self):
        """Test duration formatting for minutes and seconds."""
        assert _format_duration(60) == "1m 0s"
        assert _format_duration(90) == "1m 30s"
        assert _format_duration(3599) == "59m 59s"

    def test_format_duration_hours(self):
        """Test duration formatting for hours."""
        assert _format_duration(3600) == "1h 0m 0s"
        assert _format_duration(3661) == "1h 1m 1s"
        assert _format_duration(7325) == "2h 2m 5s"

    def test_calculate_risk_level_critical(self, sample_vulnerabilities):
        """Test risk level calculation with critical vulnerabilities."""
        risk = _calculate_risk_level(sample_vulnerabilities)
        assert risk == "Critical"

    def test_calculate_risk_level_none(self):
        """Test risk level when no vulnerabilities exist."""
        assert _calculate_risk_level([]) == "None"

    def test_calculate_risk_level_high_only(self):
        """Test risk level with only high severity."""
        vulns = [{"severity": "High"}]
        assert _calculate_risk_level(vulns) == "High"

    def test_calculate_risk_level_medium_only(self):
        """Test risk level with only medium severity."""
        vulns = [{"severity": "Medium"}]
        assert _calculate_risk_level(vulns) == "Medium"

    def test_calculate_risk_level_low_only(self):
        """Test risk level with only low severity."""
        vulns = [{"severity": "Low"}]
        assert _calculate_risk_level(vulns) == "Low"

    def test_group_by_severity(self, sample_vulnerabilities):
        """Test vulnerability grouping by severity."""
        grouped = _group_by_severity(sample_vulnerabilities)

        assert "Critical" in grouped
        assert "High" in grouped
        assert "Medium" in grouped
        assert "Low" in grouped
        assert len(grouped["Critical"]) == 1
        assert len(grouped["High"]) == 1
        assert len(grouped["Medium"]) == 1
        assert len(grouped["Low"]) == 1

    def test_group_by_severity_empty(self):
        """Test grouping with no vulnerabilities."""
        grouped = _group_by_severity([])

        for severity in SEVERITY_ORDER:
            assert severity in grouped
            assert grouped[severity] == []


# =============================================================================
# SECTION GENERATION TESTS
# =============================================================================

class TestSectionGeneration:
    """Tests for individual report section generation."""

    def test_generate_executive_summary(self, sample_scan_results):
        """Test executive summary section generation."""
        summary = _generate_executive_summary(sample_scan_results)

        assert "Security Scan Report" in summary
        assert "http://localhost:8080" in summary
        assert "Executive Summary" in summary
        assert "Risk Assessment" in summary
        assert "Vulnerability Breakdown" in summary
        # Check statistics
        assert "150" in summary  # total_requests
        assert "12" in summary   # endpoints_tested

    def test_generate_executive_summary_with_error(self, sample_scan_results):
        """Test executive summary with scan error."""
        sample_scan_results["error"] = "Connection timeout"
        summary = _generate_executive_summary(sample_scan_results)

        assert "Scan Error" in summary
        assert "Connection timeout" in summary

    def test_generate_vulnerability_findings(self, sample_scan_results):
        """Test vulnerability findings section generation."""
        findings = _generate_vulnerability_findings(sample_scan_results)

        assert "Vulnerability Findings" in findings
        assert "Critical Severity" in findings
        assert "High Severity" in findings
        assert "SQL Injection" in findings
        assert "Cross-Site Scripting" in findings
        assert "Evidence" in findings

    def test_generate_vulnerability_findings_empty(self, empty_scan_results):
        """Test findings section with no vulnerabilities."""
        findings = _generate_vulnerability_findings(empty_scan_results)

        assert "No vulnerabilities were detected" in findings

    def test_generate_recommendations(self, sample_scan_results):
        """Test recommendations section generation."""
        recommendations = _generate_recommendations(sample_scan_results)

        assert "Remediation Recommendations" in recommendations
        assert "prioritized by severity" in recommendations
        assert "General Security Best Practices" in recommendations
        assert "OWASP" in recommendations

    def test_generate_recommendations_empty(self, empty_scan_results):
        """Test recommendations with no vulnerabilities."""
        recommendations = _generate_recommendations(empty_scan_results)
        assert recommendations == ""

    def test_generate_scan_metadata(self, sample_scan_results):
        """Test scan metadata section generation."""
        metadata = _generate_scan_metadata(sample_scan_results)

        assert "Scan Details" in metadata
        assert "AI Model Information" in metadata
        assert "llama3:latest" in metadata
        assert "Tested Attack Vectors" in metadata
        assert "SQL Injection" in metadata
        assert "Detected Technologies" in metadata
        assert "Apache" in metadata


# =============================================================================
# FULL REPORT GENERATION TESTS
# =============================================================================

class TestReportGeneration:
    """Tests for complete report generation."""

    def test_generate_report_with_vulnerabilities(self, sample_scan_results):
        """Test full report generation with findings."""
        report = generate_report(sample_scan_results)

        # Check main sections are present
        assert "# 🛡️ Security Scan Report" in report
        assert "## Executive Summary" in report
        assert "## Vulnerability Findings" in report
        assert "## Remediation Recommendations" in report
        assert "## Scan Details" in report

        # Check content
        assert "http://localhost:8080" in report
        assert "SQL Injection" in report
        assert "Cross-Site Scripting" in report
        assert "llama3:latest" in report

    def test_generate_report_no_vulnerabilities(self, empty_scan_results):
        """Test report generation with clean scan."""
        report = generate_report(empty_scan_results)

        assert "Security Scan Report" in report
        assert "No vulnerabilities were detected" in report
        assert "Remediation Recommendations" not in report or "prioritized" not in report

    def test_generate_report_invalid_input(self):
        """Test ValueError for invalid input types."""
        with pytest.raises(ValueError) as exc_info:
            generate_report("not a dictionary")

        assert "must be a dictionary" in str(exc_info.value)

        with pytest.raises(ValueError):
            generate_report(None)

        with pytest.raises(ValueError):
            generate_report([{"vulnerabilities": []}])

    def test_generate_report_minimal_input(self):
        """Test report with minimal valid input."""
        minimal_results = {
            "target_url": "http://example.com",
            "vulnerabilities": [],
            "statistics": {},
            "model_info": {},
            "tested_vectors": {},
            "technology_hints": {},
        }

        report = generate_report(minimal_results)
        assert "Security Scan Report" in report
        assert "http://example.com" in report


# =============================================================================
# FILE OPERATIONS TESTS
# =============================================================================

class TestSaveReport:
    """Tests for report file saving functionality."""

    def test_save_report(self, sample_scan_results):
        """Test basic report file creation."""
        report = generate_report(sample_scan_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = save_report(report, output_dir=tmpdir)

            assert os.path.exists(filepath)
            assert filepath.endswith(".md")

            # Verify content was written
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                assert "Security Scan Report" in content

    def test_save_report_custom_filename(self, sample_scan_results):
        """Test saving with custom filename."""
        report = generate_report(sample_scan_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = save_report(
                report,
                output_dir=tmpdir,
                filename="my_custom_report.md"
            )

            assert "my_custom_report.md" in filepath
            assert os.path.exists(filepath)

    def test_save_report_filename_without_extension(self, sample_scan_results):
        """Test filename extension is added if missing."""
        report = generate_report(sample_scan_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = save_report(
                report,
                output_dir=tmpdir,
                filename="report_without_ext"
            )

            assert filepath.endswith(".md")
            assert os.path.exists(filepath)

    def test_save_report_creates_directory(self, sample_scan_results):
        """Test directory creation for output."""
        report = generate_report(sample_scan_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            nested_dir = os.path.join(tmpdir, "nested", "reports", "output")
            filepath = save_report(report, output_dir=nested_dir)

            assert os.path.exists(nested_dir)
            assert os.path.exists(filepath)

    def test_save_report_returns_absolute_path(self, sample_scan_results):
        """Test that absolute path is returned."""
        report = generate_report(sample_scan_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = save_report(report, output_dir=tmpdir)

            assert os.path.isabs(filepath)

    def test_save_report_default_filename_format(self, sample_scan_results):
        """Test default filename includes timestamp."""
        report = generate_report(sample_scan_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = save_report(report, output_dir=tmpdir)

            filename = os.path.basename(filepath)
            assert filename.startswith("dast_report_")
            assert ".md" in filename


# =============================================================================
# EDGE CASES AND SPECIAL SCENARIOS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_report_with_special_characters(self):
        """Test report handles special characters in payloads."""
        results = {
            "target_url": "http://example.com",
            "vulnerabilities": [{
                "type": "XSS",
                "severity": "High",
                "confidence": "High",
                "evidence": "<script>alert('test')</script>",
                "url": "http://example.com/?q=<script>",
                "method": "GET",
                "payload": "<script>alert(document.cookie)</script>",
            }],
            "statistics": {"total_requests": 10},
            "model_info": {"model": "test"},
            "tested_vectors": {},
            "technology_hints": {},
        }

        report = generate_report(results)
        assert "XSS" in report
        # Special characters should be present in the report
        assert "<script>" in report or "script" in report

    def test_report_with_very_long_evidence(self):
        """Test evidence truncation in report."""
        long_evidence = "x" * 5000  # Very long evidence string

        results = {
            "target_url": "http://example.com",
            "vulnerabilities": [{
                "type": "Information Disclosure",
                "severity": "Medium",
                "confidence": "Medium",
                "evidence": long_evidence,
                "url": "http://example.com/",
                "method": "GET",
            }],
            "statistics": {},
            "model_info": {},
            "tested_vectors": {},
            "technology_hints": {},
        }

        report = generate_report(results)
        # Evidence should be truncated
        assert "[truncated]" in report

    def test_report_multiple_same_severity(self):
        """Test report with multiple vulnerabilities of same severity."""
        results = {
            "target_url": "http://example.com",
            "vulnerabilities": [
                {
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "confidence": "High",
                    "evidence": "Error 1",
                    "url": "http://example.com/a",
                    "method": "GET",
                },
                {
                    "type": "Command Injection",
                    "severity": "Critical",
                    "confidence": "High",
                    "evidence": "Error 2",
                    "url": "http://example.com/b",
                    "method": "POST",
                },
            ],
            "statistics": {},
            "model_info": {},
            "tested_vectors": {},
            "technology_hints": {},
        }

        report = generate_report(results)
        assert "Critical Severity (2 found)" in report
        assert "SQL Injection" in report
        assert "Command Injection" in report

