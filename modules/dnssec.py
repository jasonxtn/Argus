import os
import sys
import dns.resolver
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain  


init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
            Argus - DNSSEC Check
    =============================================
    """)

def check_dnssec(domain):
    try:
        resolver = dns.resolver.Resolver()
        result = resolver.resolve(domain, 'DNSKEY')
        return [key.to_text() for key in result]
    except dns.resolver.NoAnswer:
        console.print(Fore.YELLOW + "[!] No DNSSEC records found.")
        return None
    except dns.resolver.NXDOMAIN:
        console.print(Fore.RED + f"[!] Domain {domain} does not exist.")
        return None
    except dns.exception.DNSException as e:
        console.print(Fore.RED + f"[!] Error retrieving DNSSEC information: {e}")
        return None

def display_dnssec(records):
    if records:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("DNSSEC Record", style="cyan", justify="left")

        for record in records:
            table.add_row(record)

        console.print(table)
    else:
        console.print(Fore.RED + "[!] No DNSSEC records to display.")

def main(target):
    banner()

    
    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[*] Checking DNSSEC for: {domain}")
    dnssec_records = check_dnssec(domain)

    if dnssec_records:
        display_dnssec(dnssec_records)
    else:
        console.print(Fore.RED + "[!] No DNSSEC records found.")

    console.print(Fore.WHITE + "[*] DNSSEC check completed.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain.")
        sys.exit(1)
