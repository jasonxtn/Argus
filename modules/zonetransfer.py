import sys
import os
import dns.resolver
import dns.query
import dns.exception
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
        Argus - DNS Zone Transfer Module
=============================================
[/green]
""")

def get_name_servers(domain):
    try:
        # Query for NS records to get the authoritative name servers
        console.print(f"[cyan][*] Querying name servers for domain: {domain}[/cyan]")
        answers = dns.resolver.resolve(domain, 'NS', lifetime=DEFAULT_TIMEOUT)
        name_servers = [str(rdata.target) for rdata in answers]
        return name_servers
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        console.print(f"[red][!] Failed to resolve NS records for {domain}: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red][!] An unexpected error occurred: {e}[/red]")
        return []

def attempt_zone_transfer(ns, domain):
    try:
        console.print(f"[cyan][*] Attempting zone transfer with {ns}...[/cyan]")
        # Attempt zone transfer with the authoritative name server
        zone = dns.query.xfr(ns, domain, lifetime=DEFAULT_TIMEOUT)
        records = []
        for record in zone:
            records.append(record.to_text())
        return records
    except dns.query.TransferError:
        console.print(f"[yellow][!] Zone transfer failed for {ns}.[/yellow]")
    except dns.exception.Timeout:
        console.print(f"[red][!] Zone transfer timed out for {ns}.[/red]")
    except Exception as e:
        console.print(f"[red][!] An error occurred during zone transfer with {ns}: {e}[/red]")
    return []

def display_zone_transfer_result(records, domain):
    if not records:
        console.print(f"[yellow][!] No zone transfer records found for {domain}.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold white", style="white")
    table.add_column("Record Type", justify="center", min_width=15)
    table.add_column("Details", justify="left", min_width=60)

    for record in records:
        record_parts = record.split(maxsplit=1)
        record_type = record_parts[0] if len(record_parts) > 0 else "N/A"
        details = record_parts[1] if len(record_parts) > 1 else "N/A"
        table.add_row(record_type, details)

    console.print(table)
    console.print(f"\n[cyan][*] Zone transfer completed for {domain}.[/cyan]")

def zonetransfer(target):
    banner()
    domain = clean_domain_input(target)
    name_servers = get_name_servers(domain)

    if not name_servers:
        console.print(f"[yellow][!] No name servers found for domain: {domain}[/yellow]")
        return

    all_records = []
    for ns in name_servers:
        ns_records = attempt_zone_transfer(ns, domain)
        all_records.extend(ns_records)

    display_zone_transfer_result(all_records, domain)

def main(target):
    zonetransfer(target)

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
