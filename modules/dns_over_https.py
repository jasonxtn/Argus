import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain
from config.settings import DEFAULT_TIMEOUT  


init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - DNS Over HTTPS (DoH) Check
    =============================================
    """)

def check_dns_over_https(domain):
    try:
        api_url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(api_url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            return "Supported"
        return "Not Supported"
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error checking DNS over HTTPS: {e}")
        return None

def display_dns_over_https(status):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("DoH Status", style="cyan", justify="left")
    table.add_row(status)
    console.print(table)

def main(target):
    banner()

    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[*] Checking DNS over HTTPS support for: {domain}")
    doh_status = check_dns_over_https(domain)
    if doh_status:
        display_dns_over_https(doh_status)
    else:
        console.print(Fore.RED + "[!] Could not retrieve DNS over HTTPS information.")
    
    console.print(Fore.CYAN + "[*] DNS Over HTTPS check completed.")

if __name__ == "__main__":
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
