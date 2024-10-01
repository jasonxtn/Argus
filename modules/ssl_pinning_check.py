import sys
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
import concurrent.futures

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + """
=============================================
      Argus - Advanced SSL Pinning Check
=============================================
""")

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    parsed_url = urlparse(domain)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return parsed_url.path

def check_ssl_pinning(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT, verify=True)
        pinning_headers = [value for key, value in response.headers.items() if 'Public-Key-Pins' in key]
        if pinning_headers:
            return True
        return False
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error checking SSL pinning for {domain}: {e}")
        return None

def display_ssl_pinning_result(domain, result):
    table = Table(title=f"SSL Pinning Check for {domain}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Domain", style="cyan", justify="left")
    table.add_column("SSL Pinning Status", style="green", justify="left")
    status = "Enabled" if result else "Not Enabled"
    table.add_row(domain, status)
    console.print(table)

def process_domain(domain):
    domain = clean_domain_input(domain)
    console.print(Fore.WHITE + f"[*] Checking SSL pinning for: {domain}")
    pinning_status = check_ssl_pinning(domain)
    if pinning_status is not None:
        display_ssl_pinning_result(domain, pinning_status)
    else:
        console.print(Fore.RED + f"[!] Could not retrieve SSL pinning information for {domain}.")

def main():
    banner()

    parser = argparse.ArgumentParser(description='Argus - Advanced SSL Pinning Check')
    parser.add_argument('domains', nargs='+', help='Domain(s) to check for SSL pinning')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()

    domains = args.domains

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_domain, domain): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                future.result()
            except Exception as e:
                console.print(Fore.RED + f"[!] Error processing {domain}: {e}")

    console.print(Fore.CYAN + "[*] SSL pinning check completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
