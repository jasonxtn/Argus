"""
Session management commands — save, load, list, and manage sessions.
"""

from __future__ import annotations

import argparse
from cmd2 import with_argparser, with_category
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from argus.core.session import Session

__mixin_name__ = "SessionMixin"

TEAL = "#2EC4B6"
console = Console()


class SessionMixin:
    """Session management commands for persistent reconnaissance state."""

    _session_parser = argparse.ArgumentParser(description="Manage sessions")
    _session_sub = _session_parser.add_subparsers(dest="action")
    _session_sub.add_parser("save", help="Save current session")
    _session_sub.add_parser("list", help="List saved sessions")
    _load_sub = _session_sub.add_parser("load", help="Load a session")
    _load_sub.add_argument("session_id", help="Session ID to load")
    _session_sub.add_parser("info", help="Current session info")
    _session_sub.add_parser("new", help="Start a new session")
    _session_sub.add_parser("findings", help="Show all findings in current session")

    @with_argparser(_session_parser)
    @with_category("Session")
    def do_session(self, args) -> None:
        """Manage reconnaissance sessions."""
        match args.action:
            case "save":
                self._session_save()
            case "list":
                self._session_list()
            case "load":
                self._session_load(args.session_id)
            case "info":
                self._session_info()
            case "new":
                self._session_new()
            case "findings":
                self._session_findings()
            case _:
                self._session_info()

    def _ensure_session(self) -> Session:
        if not hasattr(self, '_session') or self._session is None:
            self._session = Session()
        return self._session

    def _session_save(self) -> None:
        session = self._ensure_session()
        path = session.save()
        console.print()
        console.print(f"[bold green]Session saved:[/bold green] {session.id}")
        console.print(f"[dim]Path: {path}[/dim]")
        console.print()

    def _session_list(self) -> None:
        sessions = Session.list_sessions()
        console.print()
        header = Text(" Saved Sessions ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        if not sessions:
            console.print("  [dim]No saved sessions found.[/dim]")
            console.print()
            return

        table = Table(box=box.SIMPLE, header_style="bold white")
        table.add_column("ID", style=f"bold {TEAL}")
        table.add_column("Status", justify="center")
        table.add_column("Updated")

        import datetime
        for s in sessions:
            status_style = {
                "active": "green",
                "completed": "cyan",
                "paused": "yellow",
            }.get(s["status"], "dim")

            updated = ""
            if s.get("updated_at"):
                updated = datetime.datetime.fromtimestamp(s["updated_at"]).strftime("%Y-%m-%d %H:%M")

            table.add_row(
                s["id"],
                Text(s["status"], style=status_style),
                updated,
            )

        console.print(table)
        console.print()
        console.print(Text("  Use 'session load <id>' to resume", style="dim"))
        console.print()

    def _session_load(self, session_id: str) -> None:
        session = Session.load(session_id)
        if session is None:
            console.print(f"[red]Session '{session_id}' not found.[/red]")
            return

        self._session = session
        session.resume()
        console.print()
        console.print(f"[bold green]Session loaded:[/bold green] {session_id}")
        console.print(f"  Status: {session.status}")
        console.print(f"  Notes: {len(session.notes)}")
        console.print()

    def _session_info(self) -> None:
        session = self._ensure_session()
        meta = session.get_meta()

        console.print()
        header = Text(" Session Info ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        import datetime
        info = [
            ("Session ID", meta.session_id),
            ("Status", meta.status),
            ("Target", meta.target or "Not set"),
            ("Profile", meta.profile or "Not set"),
            ("Modules Run", str(meta.module_count)),
            ("Findings", str(meta.finding_count)),
            ("Created", datetime.datetime.fromtimestamp(meta.created_at).strftime("%Y-%m-%d %H:%M")),
        ]

        for label, value in info:
            line = Text()
            line.append(f"  {label}:".ljust(16), style="cyan")
            line.append(value, style="green")
            console.print(line)

        if session.notes:
            console.print()
            console.print("  [bold]Notes:[/bold]")
            for note in session.notes[-5:]:
                console.print(f"    - {note}")

        console.print()

    def _session_new(self) -> None:
        self._session = Session()
        console.print()
        console.print(f"[bold green]New session started:[/bold green] {self._session.id}")
        console.print()

    def _session_findings(self) -> None:
        session = self._ensure_session()
        findings = session.context.all_findings

        console.print()
        header = Text(" Session Findings ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        if not findings:
            console.print("  [dim]No findings yet. Run a scan first.[/dim]")
            console.print()
            return

        # Summary by severity
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        severity_styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "green",
        }

        summary = Text("  ")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count:
                style = severity_styles.get(sev, "white")
                summary.append(f"{sev.upper()}: {count}  ", style=style)

        console.print(summary)
        console.print()

        # Show critical/high findings
        important = [f for f in findings if f.severity in ("critical", "high")]
        if important:
            table = Table(title="Critical & High Findings", box=box.SIMPLE, header_style="bold")
            table.add_column("Module", style="cyan")
            table.add_column("Severity", justify="center")
            table.add_column("Finding")

            for f in important[:20]:
                style = severity_styles.get(f.severity, "white")
                table.add_row(f.module_id, Text(f.severity.upper(), style=style), f.title[:80])

            console.print(table)

        # Category breakdown
        console.print()
        cat_counts = {}
        for f in findings:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

        console.print("  [bold]By Category:[/bold]")
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            console.print(f"    {cat}: {count}")

        console.print()
        console.print(f"  [bold]Total: {len(findings)} findings[/bold]")
        console.print()

    @with_category("Session")
    def do_note(self, line: str) -> None:
        """Add a note to the current session."""
        note = line.strip()
        if not note:
            self.perror("Usage: note <text>")
            return

        session = self._ensure_session()
        session.add_note(note)
        console.print(f"[green]Note added to session {session.id}[/green]")
