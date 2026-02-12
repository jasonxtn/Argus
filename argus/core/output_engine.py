"""
Layer 4: Output Engine
Structured output formatting with output contracts, multiple export formats,
and configurable report profiles.
"""

from __future__ import annotations

import json
import os
import datetime
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Literal, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from argus.core.severity import SeverityScore, severity_to_legacy


console = Console()
TEAL = "#2EC4B6"


@dataclass
class ModuleResult:
    """Structured output contract for a single module execution."""
    module_id: str
    module_name: str
    target: str
    status: Literal["success", "partial", "error", "skipped"]
    raw_output: str
    severity: SeverityScore
    execution_time: float
    findings_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    @property
    def severity_label(self) -> str:
        return self.severity.normalized_label

    @property
    def legacy_severity(self) -> str:
        return severity_to_legacy(self.severity)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "module_id": self.module_id,
            "module_name": self.module_name,
            "target": self.target,
            "status": self.status,
            "severity": self.severity_label,
            "severity_score": self.severity.total,
            "execution_time": round(self.execution_time, 2),
            "findings_count": self.findings_count,
            "timestamp": self.timestamp,
        }
        return d


@dataclass
class AssessmentReport:
    """Complete assessment report — aggregates all module results."""
    target: str
    profile: str
    started_at: str
    completed_at: Optional[str] = None
    module_results: List[ModuleResult] = field(default_factory=list)
    total_findings: int = 0
    quality_score: Optional[int] = None

    def add_result(self, result: ModuleResult) -> None:
        self.module_results.append(result)
        self.total_findings += result.findings_count

    def finalize(self) -> None:
        self.completed_at = datetime.datetime.now().isoformat()

    @property
    def severity_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in self.module_results:
            label = r.severity_label
            if label in counts:
                counts[label] += 1
        return counts

    @property
    def success_rate(self) -> float:
        if not self.module_results:
            return 0.0
        ok = sum(1 for r in self.module_results if r.status == "success")
        return ok / len(self.module_results) * 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "module_count": len(self.module_results),
            "total_findings": self.total_findings,
            "severity_summary": self.severity_summary,
            "success_rate": round(self.success_rate, 1),
            "quality_score": self.quality_score,
            "modules": [r.to_dict() for r in self.module_results],
        }


# --- Report Profiles ---

REPORT_PROFILES = {
    "executive": {
        "format": "txt",
        "sections": ["summary", "critical_findings", "recommendations"],
        "detail_level": "high-level",
    },
    "technical": {
        "format": "json",
        "sections": ["all_findings", "raw_data", "methodology"],
        "detail_level": "detailed",
    },
    "compact": {
        "format": "txt",
        "sections": ["summary", "severity_table"],
        "detail_level": "minimal",
    },
}


# --- Output Renderers ---

class OutputEngine:
    """Renders assessment results in various formats."""

    def render_module_result(self, result: ModuleResult) -> None:
        """Display a single module result with severity coloring."""
        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "green",
        }
        color = severity_colors.get(result.severity_label, "white")

        header = Text()
        header.append(f" {result.module_name} ", style=f"bold white on {TEAL}")
        header.append(f"  [{result.severity_label.upper()}]", style=color)
        header.append(f"  {result.execution_time:.1f}s", style="dim")

        console.print()
        console.print(header)

    def render_assessment_summary(self, report: AssessmentReport) -> None:
        """Display the final assessment summary with severity breakdown."""
        console.print()

        # Header
        title = Text(f" Assessment Report: {report.target} ", style=f"bold white on {TEAL}")
        console.print(Panel(title, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        # Severity breakdown table
        sev = report.severity_summary
        table = Table(
            title="Severity Summary",
            box=box.ROUNDED,
            header_style="bold white",
            show_lines=False,
        )
        table.add_column("Level", style="bold")
        table.add_column("Count", justify="center")
        table.add_column("Bar", min_width=20)

        severity_styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "green",
        }

        total = max(sum(sev.values()), 1)
        for level in ["critical", "high", "medium", "low", "info"]:
            count = sev[level]
            bar_len = int(count / total * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            style = severity_styles[level]
            table.add_row(
                Text(level.upper(), style=style),
                str(count),
                Text(bar, style=style),
            )

        console.print(table)
        console.print()

        # Stats
        stats = Text()
        stats.append("Modules: ", style="bold")
        stats.append(f"{len(report.module_results)}  ", style="green")
        stats.append("Findings: ", style="bold")
        stats.append(f"{report.total_findings}  ", style="green")
        stats.append("Success Rate: ", style="bold")
        rate_color = "green" if report.success_rate > 80 else "yellow" if report.success_rate > 50 else "red"
        stats.append(f"{report.success_rate:.0f}%  ", style=rate_color)
        if report.quality_score is not None:
            stats.append("Quality: ", style="bold")
            q_color = "green" if report.quality_score >= 85 else "yellow" if report.quality_score >= 70 else "red"
            stats.append(f"{report.quality_score}/100", style=q_color)

        console.print(stats)
        console.print()

    def render_runtimes(self, results: List[ModuleResult]) -> None:
        """Display execution time summary."""
        if not results:
            return

        table = Table(
            title="Execution Times",
            box=box.SIMPLE,
            header_style="bold",
        )
        table.add_column("Module", style="cyan")
        table.add_column("Severity", justify="center")
        table.add_column("Time", justify="right", style="dim")
        table.add_column("Status", justify="center")

        severity_styles = {
            "critical": "bold red", "high": "red", "medium": "yellow",
            "low": "cyan", "info": "green",
        }
        status_icons = {
            "success": "[green]OK[/green]",
            "partial": "[yellow]PARTIAL[/yellow]",
            "error": "[red]ERR[/red]",
            "skipped": "[dim]SKIP[/dim]",
        }

        for r in sorted(results, key=lambda x: x.execution_time, reverse=True):
            style = severity_styles.get(r.severity_label, "white")
            table.add_row(
                r.module_name,
                Text(r.severity_label.upper(), style=style),
                f"{r.execution_time:.1f}s",
                status_icons.get(r.status, r.status),
            )

        console.print(table)
        console.print()

    def render_followup_suggestions(self, suggestions: List[tuple]) -> None:
        """Display suggested follow-up modules."""
        if not suggestions:
            return

        console.print()
        header = Text(" Suggested Follow-ups ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        for mid, name, script in suggestions:
            line = Text()
            line.append(f"  {mid} ", style=f"bold {TEAL}")
            line.append(f"{name} ", style="white")
            line.append(f"({script})", style="dim")
            console.print(line)

        console.print()
        console.print(Text("  Use 'run <id>' to execute", style="dim"))
        console.print()


# --- File Exporters ---

def export_json(report: AssessmentReport, output_dir: str) -> str:
    """Export assessment report as JSON."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{_safe_filename(report.target)}_report.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)

    return filepath


def export_markdown(report: AssessmentReport, output_dir: str) -> str:
    """Export assessment report as Markdown."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{_safe_filename(report.target)}_report.md"
    filepath = os.path.join(output_dir, filename)

    sev = report.severity_summary
    lines = [
        f"# Assessment Report: {report.target}",
        f"",
        f"**Profile:** {report.profile}",
        f"**Started:** {report.started_at}",
        f"**Completed:** {report.completed_at}",
        f"**Modules Run:** {len(report.module_results)}",
        f"**Total Findings:** {report.total_findings}",
        f"",
        f"## Severity Summary",
        f"",
        f"| Level | Count |",
        f"|-------|-------|",
    ]
    for level in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {level.upper()} | {sev[level]} |")

    lines.extend([
        f"",
        f"## Module Results",
        f"",
        f"| Module | Severity | Time | Status |",
        f"|--------|----------|------|--------|",
    ])
    for r in report.module_results:
        lines.append(f"| {r.module_name} | {r.severity_label.upper()} | {r.execution_time:.1f}s | {r.status} |")

    if report.quality_score is not None:
        lines.extend([f"", f"## Quality Score: {report.quality_score}/100"])

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath


def _safe_filename(s: str, max_length: int = 200) -> str:
    return re.sub(r"[^a-zA-Z0-9_.\-]", "_", s)[:max_length]
