import sys
import os
import dns.resolver
from dns.exception import DNSException
from rich.console import Console
from rich.table import Table
from colorama import Fore, init, Style

# Add parent directory to sys.path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input
from config.settings import DEFAULT_TIMEOUT

# Initialize colorama
init(autoreset=True)
console = Console()

def banner():
    console.print(f"""
{Fore.GREEN}=============================================
        Argus - TXT Record Retrieval Module
============================================={Style.RESET_ALL}
""")

def get_txt_records(domain):
    """Get the TXT records for the given domain."""
    try:
        console.print(f"{Fore.CYAN}[*] Retrieving TXT records for domain: {domain}{Style.RESET_ALL}")
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=DEFAULT_TIMEOUT)
        txt_records = [rdata.to_text() for rdata in answers]
        return txt_records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        console.print(f"{Fore.RED}[!] Failed to retrieve TXT records for {domain}: {e}{Style.RESET_ALL}")
        return []
    except Exception as e:
        console.print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
        return []

def display_txt_records(txt_records, domain):
    """Display the TXT records in a table format."""
    if not txt_records:
        console.print(f"{Fore.YELLOW}[!] No TXT records found for {domain}.{Style.RESET_ALL}")
        return

    table = Table(show_header=True, header_style="bold white")
    table.add_column("TXT Record", style="white", justify="left", min_width=60)

    for record in txt_records:
        table.add_row(record.strip('"'))

    console.print(table)
    console.print(f"\n{Fore.CYAN}[*] TXT record retrieval completed for {domain}.{Style.RESET_ALL}")

def txt_record_lookup(target):
    """Perform the TXT record lookup process for the given target."""
    banner()
    domain = clean_domain_input(target)
    txt_records = get_txt_records(domain)
    display_txt_records(txt_records, domain)

def main(target):
    txt_record_lookup(target)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
            sys.exit(0)  # Explicitly exit with code 0
        except KeyboardInterrupt:
            console.print(f"\n{Fore.RED}[!] Script interrupted by user.{Style.RESET_ALL}")
            sys.exit(0)  # Exit with code 0 to prevent errors in argus.py
        except Exception as e:
            console.print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
            sys.exit(1)  # Exit with code 1 to indicate an error
    else:
        console.print(f"{Fore.RED}[!] No target provided. Please pass a domain or IP address.{Style.RESET_ALL}")
        sys.exit(1)
