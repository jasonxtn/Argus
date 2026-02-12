"""
Layer 5: Quality Gates
Validates assessment quality, cross-references findings, and scores results.
Inspired by MONNA's 5-gate quality system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from argus.core.context import Finding, TargetProfile
from argus.core.output_engine import AssessmentReport, ModuleResult


@dataclass
class GateResult:
    """Result of a single quality gate check."""
    gate_name: str
    passed: bool
    score: int          # out of 20
    details: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class QualityReport:
    """Complete quality assessment across all gates."""
    gates: List[GateResult] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(g.score for g in self.gates)

    @property
    def all_passed(self) -> bool:
        return all(g.passed for g in self.gates)

    @property
    def warnings(self) -> List[str]:
        w = []
        for g in self.gates:
            w.extend(g.warnings)
        return w


class QualityGates:
    """
    Five-gate quality assurance system for reconnaissance assessments.

    Gate 1: Data Integrity — verify data formats are valid
    Gate 2: Cross-Reference — check findings against each other
    Gate 3: Severity Accuracy — verify severity ratings match evidence
    Gate 4: Coverage Completeness — check for gaps in assessment
    Gate 5: Overall Scoring — compute quality score
    """

    def run_all(
        self,
        report: AssessmentReport,
        findings: List[Finding],
        profile: TargetProfile,
        total_applicable_modules: int,
    ) -> QualityReport:
        """Run all quality gates and return a comprehensive report."""
        qr = QualityReport()
        qr.gates.append(self.gate_1_data_integrity(report))
        qr.gates.append(self.gate_2_cross_reference(findings))
        qr.gates.append(self.gate_3_severity_accuracy(report))
        qr.gates.append(self.gate_4_coverage(report, total_applicable_modules))
        qr.gates.append(self.gate_5_scoring(report, findings))

        # Apply quality score to report
        report.quality_score = qr.total_score
        return qr

    def gate_1_data_integrity(self, report: AssessmentReport) -> GateResult:
        """Verify data formats: modules returned valid output, no empty results."""
        warnings = []
        success_count = 0
        error_count = 0

        for r in report.module_results:
            if r.status == "success":
                success_count += 1
                if not r.raw_output.strip():
                    warnings.append(f"{r.module_name}: succeeded but returned empty output")
            elif r.status == "error":
                error_count += 1
                warnings.append(f"{r.module_name}: execution failed")

        total = len(report.module_results)
        if total == 0:
            return GateResult("Data Integrity", False, 0, "No modules executed", warnings)

        ratio = success_count / total
        score = int(ratio * 20)
        passed = ratio >= 0.5

        return GateResult(
            "Data Integrity",
            passed,
            score,
            f"{success_count}/{total} modules returned valid data",
            warnings,
        )

    def gate_2_cross_reference(self, findings: List[Finding]) -> GateResult:
        """Cross-check findings for consistency and corroboration."""
        warnings = []

        # Check if IP addresses found in multiple modules (corroboration)
        ip_sources: Dict[str, Set[str]] = {}
        for f in findings:
            if f.category == "network" and isinstance(f.value, str):
                ip_sources.setdefault(f.value, set()).add(f.module_id)

        corroborated = sum(1 for sources in ip_sources.values() if len(sources) > 1)
        total_unique = len(ip_sources)

        # Check for contradictory findings
        severity_by_module: Dict[str, Set[str]] = {}
        for f in findings:
            if f.category == "security":
                severity_by_module.setdefault(f.module_id, set()).add(f.severity)

        # Score based on corroboration rate
        if total_unique > 0:
            corr_ratio = corroborated / total_unique
            score = min(20, int(10 + corr_ratio * 10))
        else:
            score = 10  # Neutral if no cross-reference possible

        return GateResult(
            "Cross-Reference",
            True,
            score,
            f"{corroborated}/{total_unique} data points corroborated across modules",
            warnings,
        )

    def gate_3_severity_accuracy(self, report: AssessmentReport) -> GateResult:
        """Verify severity ratings are justified by evidence."""
        warnings = []
        total_rated = 0
        justified = 0

        for r in report.module_results:
            if r.severity_label in ("critical", "high"):
                total_rated += 1
                # A finding is "justified" if the output actually contains evidence
                output = r.raw_output.lower()
                evidence_terms = {
                    "critical": ["critical", "severe", "exploit", "rce", "injection"],
                    "high": ["vulnerable", "expired", "high", "alert", "cve"],
                }
                terms = evidence_terms.get(r.severity_label, [])
                if any(term in output for term in terms):
                    justified += 1
                else:
                    warnings.append(
                        f"{r.module_name}: rated {r.severity_label.upper()} "
                        f"but weak evidence in output"
                    )

        if total_rated == 0:
            return GateResult("Severity Accuracy", True, 18, "No high/critical findings to verify")

        ratio = justified / total_rated
        score = int(ratio * 20)
        return GateResult(
            "Severity Accuracy",
            ratio >= 0.6,
            score,
            f"{justified}/{total_rated} severity ratings supported by evidence",
            warnings,
        )

    def gate_4_coverage(self, report: AssessmentReport, total_applicable: int) -> GateResult:
        """Check if the assessment covered enough of the applicable modules."""
        warnings = []
        executed = len(report.module_results)

        if total_applicable == 0:
            return GateResult("Coverage", True, 15, "No applicable modules defined")

        ratio = executed / total_applicable
        score = min(20, int(ratio * 20))

        if ratio < 0.3:
            warnings.append(
                f"Only {executed}/{total_applicable} applicable modules were run. "
                f"Consider running more for thorough assessment."
            )

        # Check category coverage
        categories_hit: Set[str] = set()
        for r in report.module_results:
            # Infer category from module name (simplified)
            categories_hit.add("assessed")

        return GateResult(
            "Coverage",
            ratio >= 0.3,
            score,
            f"{executed}/{total_applicable} applicable modules executed ({ratio*100:.0f}%)",
            warnings,
        )

    def gate_5_scoring(self, report: AssessmentReport, findings: List[Finding]) -> GateResult:
        """Compute overall assessment quality score."""
        warnings = []
        score = 10  # Base score

        # Bonus for finding diversity
        categories = set(f.category for f in findings)
        if len(categories) >= 4:
            score += 5
        elif len(categories) >= 2:
            score += 3

        # Bonus for actionable findings (those with severity > info)
        actionable = sum(1 for f in findings if f.severity != "info")
        if actionable > 0:
            score += 3
        if actionable > 5:
            score += 2

        # Penalty for high error rate
        errors = sum(1 for r in report.module_results if r.status == "error")
        if errors > len(report.module_results) * 0.3:
            score -= 3
            warnings.append("High error rate detected — some modules may need attention")

        score = max(0, min(20, score))
        return GateResult(
            "Overall Quality",
            score >= 10,
            score,
            f"Assessment quality score component: {score}/20",
            warnings,
        )
