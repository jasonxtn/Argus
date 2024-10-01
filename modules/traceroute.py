import sys
import os
import platform
import subprocess
from rich.console import Console
from rich.table import Table

# Add parent directory to sys.path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input
from config.settings import DEFAULT_TIMEOUT

console = Console()

def banner():
    console.print("""
[green]
=============================================
        Argus - Traceroute Module
=============================================
[/green]
""")

class Traceroute:
    def __init__(self, target):
        self.target = clean_domain_input(target)
        self.command = self._determine_command()

    def _determine_command(self):
        # Determine the operating system and the appropriate command
        system_platform = platform.system()
        if system_platform == "Windows":
            return ["tracert", self.target]
        elif system_platform in ("Linux", "Darwin"):
            return ["traceroute", self.target]
        else:
            console.print(f"[red][!] Unsupported operating system: {system_platform}[/red]")
            return None

    def run(self):
        if not self.command:
            return None

        try:
            console.print(f"[cyan][*] Running traceroute on {self.target}...[/cyan]")
            result = subprocess.run(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=DEFAULT_TIMEOUT * 10  # Using the existing timeout configuration
            )
            return result.stdout if result.stdout else result.stderr

        except subprocess.TimeoutExpired:
            console.print("[red][!] Traceroute command timed out.[/red]")
            return None
        except FileNotFoundError:
            console.print("[red][!] Traceroute command not found. Please ensure it is installed on your system.[/red]")
            return None
        except Exception as e:
            console.print(f"[red][!] An error occurred while running traceroute: {e}[/red]")
            return None

def parse_traceroute_output(output):
    # Split output into lines and extract meaningful information
    lines = output.splitlines()
    hops = []

    for line in lines:
        line = line.strip()
        if line and (line[0].isdigit() or "*" in line):
            hops.append(line)

    return hops

def display_traceroute_result(hops):
    if not hops:
        console.print("[yellow][!] No hops were found in the traceroute output.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Hop", style="white", justify="center", min_width=5)
    table.add_column("Details", style="white", justify="left", min_width=50)

    for hop in hops:
        # Split each hop line into parts to extract hop number and details
        parts = hop.split(maxsplit=1)
        hop_number = parts[0] if len(parts) > 0 else "N/A"
        details = parts[1] if len(parts) > 1 else "N/A"
        table.add_row(hop_number, details)

    console.print(table)
    console.print(f"\n[cyan][*] Traceroute completed.[/cyan]")

def traceroute(target):
    banner()
    tracer = Traceroute(target)
    output = tracer.run()
    if output:
        hops = parse_traceroute_output(output)
        display_traceroute_result(hops)
    else:
        console.print("[yellow][!] Traceroute did not produce any output.[/yellow]")

def main(target):
    traceroute(target)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
            sys.exit(0)  # Explicitly exit with code 0
        except KeyboardInterrupt:
            console.print("\n[red][!] Script interrupted by user.[/red]")
            sys.exit(0)  # Exit with code 0 to prevent errors in argus.py
        except Exception as e:
            console.print(f"[red][!] An unexpected error occurred: {e}[/red]")
            sys.exit(1)  # Exit with code 1 to indicate an error
    else:
        console.print("[red][!] No target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
