"""
Scan command — Pipeline-powered reconnaissance with adaptive profiles.
Includes the Scan Wizard for guided assessment setup.
"""

from __future__ import annotations

import argparse
from typing import List

from cmd2 import with_argparser, with_category
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

from argus.core.pipeline import ReconPipeline
from argus.core.session import Session
from argus.core.dependencies import SCAN_PROFILES
from argus.cli.router import detect_target_type, TargetType
from argus.core.catalog_cache import SECTION_TOOL_NUMBERS

__mixin_name__ = "ScanMixin"

TEAL = "#2EC4B6"
console = Console()


class ScanMixin:
    """Pipeline-integrated scan commands."""

    _scan_parser = argparse.ArgumentParser(description="Run an adaptive scan through the pipeline")
    _scan_parser.add_argument("target", nargs="?", help="Target domain/IP/URL")
    _scan_parser.add_argument("--profile", "-p", choices=list(SCAN_PROFILES.keys()),
                              default="standard", help="Scan profile")
    _scan_parser.add_argument("--no-chain", action="store_true",
                              help="Disable context chaining between modules")
    _scan_parser.add_argument("--export", choices=["json", "markdown", "md"],
                              help="Export report format")
    _scan_parser.add_argument("--no-followups", action="store_true",
                              help="Don't show follow-up suggestions")

    @with_argparser(_scan_parser)
    @with_category("Pipeline")
    def do_scan(self, args) -> None:
        """Run a full pipeline-powered scan with adaptive profiles."""
        target = args.target or self.target
        if not target:
            target = Prompt.ask("Enter target domain, IP, or URL")
        self.target = target

        profile_def = SCAN_PROFILES.get(args.profile, {})

        console.print()
        header = Text(f" Scan: {args.profile.upper()} ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        # Show scan plan
        target_type = detect_target_type(target)
        console.print(f"  Target:  [bold]{target}[/bold]")
        console.print(f"  Type:    [cyan]{target_type.value}[/cyan]")
        console.print(f"  Profile: [green]{args.profile}[/green] — {profile_def.get('description', '')}")
        console.print(f"  Chain:   {'[green]ON[/green]' if not args.no_chain else '[yellow]OFF[/yellow]'}")
        console.print()

        # Initialize pipeline with session
        if not hasattr(self, '_session') or self._session is None:
            self._session = Session()

        pipeline = ReconPipeline(session=self._session)

        # Execute
        pipeline.execute(
            target=target,
            profile=args.profile,
            threads=self.threads,
            cli_ctx=self,
            context_chaining=not args.no_chain,
            show_followups=not args.no_followups,
            export_format=args.export,
        )

        self._print_status_bar()

    @with_category("Pipeline")
    def do_wizard(self, _line) -> None:
        """Interactive scan wizard — guided assessment setup."""
        console.print()
        header = Text(" Scan Wizard ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        # Step 1: What are you assessing?
        console.print("  [bold]What are you assessing?[/bold]")
        console.print()
        options = [
            ("1", "Web Application", "web"),
            ("2", "Network Infrastructure", "infrastructure"),
            ("3", "Email Security", "email"),
            ("4", "SSL/TLS Configuration", "ssl"),
            ("5", "Full OSINT Profile", "full"),
            ("6", "Stealth Recon (passive only)", "stealth"),
        ]
        for num, label, _ in options:
            console.print(f"    [bold {TEAL}]{num}.[/bold {TEAL}] {label}")
        console.print()

        choice = Prompt.ask("  Select", choices=[o[0] for o in options], default="5")
        assessment_type = next(o[2] for o in options if o[0] == choice)

        # Step 2: Target
        console.print()
        target = Prompt.ask("  Enter target (domain/IP/URL)")
        self.target = target
        target_type = detect_target_type(target)

        console.print(f"  [dim]Detected type: {target_type.value}[/dim]")

        # Step 3: Profile
        console.print()
        console.print("  [bold]Scan intensity?[/bold]")
        console.print()
        for name, profile in SCAN_PROFILES.items():
            desc = profile.get("description", "")
            console.print(f"    [bold {TEAL}]{name}[/bold {TEAL}]  {desc}")
        console.print()

        profile = Prompt.ask(
            "  Profile",
            choices=list(SCAN_PROFILES.keys()),
            default="standard",
        )

        # Step 4: Map assessment type to category/profile
        category = None
        if assessment_type == "web":
            category = "web"
        elif assessment_type == "infrastructure":
            category = "network"
        elif assessment_type in ("email", "ssl"):
            category = "security"
        elif assessment_type == "stealth":
            profile = "stealth"
        # "full" uses the profile's default behavior

        # Step 5: Confirmation
        console.print()
        console.print("  [bold]Scan Plan:[/bold]")
        console.print(f"    Target:     [bold]{target}[/bold] ({target_type.value})")
        console.print(f"    Assessment: [cyan]{assessment_type}[/cyan]")
        console.print(f"    Profile:    [green]{profile}[/green]")
        console.print(f"    Threads:    {self.threads}")
        if category:
            console.print(f"    Category:   {category}")
        console.print()

        if not Confirm.ask("  Proceed?", default=True):
            console.print("  [dim]Cancelled.[/dim]")
            return

        # Execute
        console.print()

        if not hasattr(self, '_session') or self._session is None:
            self._session = Session()

        pipeline = ReconPipeline(session=self._session)
        pipeline.execute(
            target=target,
            category=category,
            profile=profile,
            threads=self.threads,
            cli_ctx=self,
            context_chaining=True,
            show_followups=True,
        )

        self._print_status_bar()

    _pscan_parser = argparse.ArgumentParser(description="Quick pipeline scan with explicit modules")
    _pscan_parser.add_argument("ids", nargs="+", help="Module IDs to run through pipeline")
    _pscan_parser.add_argument("--export", choices=["json", "markdown", "md"],
                               help="Export report format")

    @with_argparser(_pscan_parser)
    @with_category("Pipeline")
    def do_pscan(self, args) -> None:
        """Run specific modules through the pipeline (with context chaining & quality gates)."""
        if not self.target:
            self._prompt_target_if_needed()

        from argus.cli.helpers import resolve_module_number, fuzzy_find_modules
        mod_ids = []
        for tok in args.ids:
            if tok.isdigit():
                resolved = resolve_module_number(tok)
                if resolved:
                    mod_ids.append(resolved)
            else:
                matches = fuzzy_find_modules(tok)
                if matches:
                    mod_ids.append(matches[0]["number"])

        if not mod_ids:
            self.perror("No valid module IDs found.")
            return

        if not hasattr(self, '_session') or self._session is None:
            self._session = Session()

        pipeline = ReconPipeline(session=self._session)
        pipeline.execute(
            target=self.target,
            module_ids=mod_ids,
            threads=self.threads,
            cli_ctx=self,
            export_format=args.export,
        )

        self._print_status_bar()

    @with_category("Pipeline")
    def do_profiles(self, _line) -> None:
        """List available scan profiles."""
        console.print()
        header = Text(" Scan Profiles ", style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        table = Table(box=box.SIMPLE, header_style="bold white")
        table.add_column("Profile", style=f"bold {TEAL}")
        table.add_column("Description", style="white")
        table.add_column("Modules", justify="center")
        table.add_column("Timeout", justify="right", style="dim")

        for name, profile in SCAN_PROFILES.items():
            mod_count = len(profile.get("modules", []))
            if not mod_count and "categories" in profile:
                for cat in profile["categories"]:
                    cat_map = {
                        "network": "Network & Infrastructure",
                        "web": "Web Application Analysis",
                        "security": "Security & Threat Intelligence",
                    }
                    mod_count += len(SECTION_TOOL_NUMBERS.get(cat_map.get(cat, cat), []))
            table.add_row(
                name,
                profile.get("description", ""),
                str(mod_count) if mod_count else "auto",
                f"{profile.get('timeout', 0)}s",
            )

        console.print(table)
        console.print()
        console.print(Text("  Use 'scan --profile <name> <target>' to run", style="dim"))
        console.print()
        self._print_status_bar()
