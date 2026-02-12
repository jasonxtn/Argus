"""
Pipeline Orchestrator
The central nervous system — coordinates all 5 layers into a unified execution flow.

    User Input → Router → Context → Execution → Output → Quality → Final Output
"""

from __future__ import annotations

import time
import datetime
from typing import Dict, List, Optional

from rich.console import Console

from argus.cli.router import TaskPlan, route, detect_target_type, TargetType
from argus.core.context import ContextEngine
from argus.core.dependencies import get_execution_order, suggest_followups
from argus.core.output_engine import (
    AssessmentReport,
    ModuleResult,
    OutputEngine,
    export_json,
    export_markdown,
)
from argus.core.quality import QualityGates, QualityReport
from argus.core.runner import execute_script
from argus.core.severity import score_output
from argus.core.session import Session
from argus.core.catalog_cache import tools_mapping

console = Console()


class ReconPipeline:
    """
    Orchestrates the full reconnaissance pipeline:
    Layer 1: Command Router (plan the scan)
    Layer 2: Context Engine (shared intelligence)
    Layer 3: Execution Engine (run modules)
    Layer 4: Output Engine (format results)
    Layer 5: Quality Gates (validate & score)
    """

    def __init__(self, session: Optional[Session] = None):
        self.session = session or Session()
        self.context = self.session.context
        self.output = OutputEngine()
        self.quality = QualityGates()

    def execute(
        self,
        target: str,
        module_ids: Optional[List[str]] = None,
        category: Optional[str] = None,
        profile: Optional[str] = None,
        threads: int = 1,
        options: Optional[Dict] = None,
        cli_ctx=None,
        context_chaining: bool = True,
        show_followups: bool = True,
        export_format: Optional[str] = None,
    ) -> AssessmentReport:
        """
        Execute the full pipeline.

        Args:
            target: The scan target (domain, IP, URL)
            module_ids: Explicit list of module IDs to run
            category: Category to scan (infrastructure, web, security)
            profile: Scan profile (quick, standard, deep, stealth)
            threads: Number of threads per module
            options: Module options
            cli_ctx: CLI context for backward compatibility
            context_chaining: Whether to feed results between modules
            show_followups: Whether to display follow-up suggestions
            export_format: Optional export format (json, markdown)
        """
        # --- Layer 1: Route ---
        plan = route(
            target=target,
            module_ids=module_ids,
            category=category,
            profile=profile,
            options=options,
        )

        if not plan.module_ids:
            console.print("[bold red]No applicable modules for this target/configuration.[/bold red]")
            return AssessmentReport(
                target=target,
                profile=profile or "manual",
                started_at=datetime.datetime.now().isoformat(),
            )

        # Start assessment
        report = self.session.start_assessment(target, profile or plan.scan_scope.value)

        # --- Layer 2 + 3: Execute with Context ---
        if context_chaining and len(plan.module_ids) > 1:
            waves = get_execution_order(plan.module_ids)
        else:
            waves = [plan.module_ids]

        for wave in waves:
            for mid in wave:
                result = self._execute_module(
                    mid, target, threads, options or {}, cli_ctx
                )
                report.add_result(result)

                # Feed results back into context
                if context_chaining and result.status == "success":
                    findings = self.context.ingest_results(mid, target, result.raw_output)
                    result.findings_count = len(findings)

                # Render individual result
                self.output.render_module_result(result)

        report.finalize()

        # --- Layer 4: Output ---
        self.output.render_assessment_summary(report)
        self.output.render_runtimes(report.module_results)

        # --- Layer 5: Quality ---
        target_profile = self.context.get_or_create_profile(target)
        total_applicable = self._count_applicable_modules(target)
        quality_report = self.quality.run_all(
            report,
            self.context.all_findings,
            target_profile,
            total_applicable,
        )
        self._display_quality(quality_report)

        # Follow-up suggestions
        if show_followups and len(plan.module_ids) > 1:
            finding_categories = set(f.category for f in self.context.all_findings)
            suggestions = suggest_followups(plan.module_ids, finding_categories)
            self.output.render_followup_suggestions(suggestions)

        # Export if requested
        if export_format:
            self._export(report, target, export_format)

        # Update CLI context for backward compatibility
        if cli_ctx:
            cli_ctx.last_run_outputs = {
                r.module_name: r.raw_output for r in report.module_results
            }
            cli_ctx.last_run_runtimes = [
                (r.module_name, r.legacy_severity, r.execution_time)
                for r in report.module_results
            ]

        return report

    def _execute_module(
        self, mid: str, target: str, threads: int,
        options: Dict, cli_ctx
    ) -> ModuleResult:
        """Execute a single module and return a structured result."""
        tool = tools_mapping.get(mid)
        if not tool or not tool.get("script"):
            return ModuleResult(
                module_id=mid,
                module_name=tool["name"] if tool else mid,
                target=target,
                status="skipped",
                raw_output="",
                severity=score_output(""),
                execution_time=0.0,
            )

        name = tool["name"]
        script = tool["script"]

        # Merge options
        allow = [o.replace("-", "_").lower() for o in (tool.get("options_meta") or [])]
        merged = self._merge_options(
            getattr(cli_ctx, "global_option_overrides", None) if cli_ctx else None,
            getattr(cli_ctx, "module_options", {}).get(mid) if cli_ctx else None,
            allow,
            options,
        )

        start = time.time()
        try:
            raw_output = execute_script(
                script, target, threads, merged,
                show_status=False,
                quiet=getattr(cli_ctx, "quiet_mode", False),
            )
            status = "success" if raw_output.strip() else "partial"
        except Exception as e:
            raw_output = str(e)
            status = "error"

        elapsed = time.time() - start
        severity = score_output(raw_output)

        # Record in CLI history
        if cli_ctx and hasattr(cli_ctx, "_record_recent"):
            cli_ctx._record_recent(mid)

        return ModuleResult(
            module_id=mid,
            module_name=name,
            target=target,
            status=status,
            raw_output=raw_output,
            severity=severity,
            execution_time=elapsed,
        )

    @staticmethod
    def _merge_options(
        global_over: Optional[Dict],
        module_opts: Optional[Dict],
        allowed: List[str],
        extra: Optional[Dict] = None,
    ) -> Dict:
        combined: Dict = {}
        if global_over:
            for k, v in global_over.items():
                if k in allowed:
                    combined[k] = v
        if module_opts:
            combined.update(module_opts)
        if extra:
            for k, v in extra.items():
                if k in allowed:
                    combined[k] = v
        return combined

    def _count_applicable_modules(self, target: str) -> int:
        """Count how many modules are applicable for this target type."""
        from argus.cli.router import _get_modules_for_target_type
        target_type = detect_target_type(target)
        return len(_get_modules_for_target_type(target_type))

    def _display_quality(self, qr: QualityReport) -> None:
        """Display quality gate results."""
        from rich.table import Table
        from rich import box

        table = Table(
            title=f"Quality Gates  [{qr.total_score}/100]",
            box=box.ROUNDED,
            header_style="bold white",
        )
        table.add_column("Gate", style="cyan")
        table.add_column("Score", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")

        for g in qr.gates:
            status = "[green]PASS[/green]" if g.passed else "[red]FAIL[/red]"
            table.add_row(g.gate_name, f"{g.score}/20", status, g.details)

        console.print(table)
        console.print()

        if qr.warnings:
            console.print("[yellow]Warnings:[/yellow]")
            for w in qr.warnings[:5]:  # Show top 5 warnings
                console.print(f"  [yellow]![/yellow] {w}")
            if len(qr.warnings) > 5:
                console.print(f"  [dim]... and {len(qr.warnings) - 5} more[/dim]")
            console.print()

    def _export(self, report: AssessmentReport, target: str, fmt: str) -> None:
        """Export the report to a file."""
        import os
        from argus.config.settings import RESULTS_DIR
        output_dir = os.path.join(os.getcwd(), RESULTS_DIR, target)

        if fmt == "json":
            path = export_json(report, output_dir)
        elif fmt in ("md", "markdown"):
            path = export_markdown(report, output_dir)
        else:
            console.print(f"[yellow]Unknown export format: {fmt}[/yellow]")
            return

        console.print(f"[green]Report exported to: {os.path.relpath(path)}[/green]")
