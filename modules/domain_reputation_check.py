import sys
import os
import requests
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import re
import argparse
import concurrent.futures
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import API_KEYS

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3
BACKOFF_FACTOR = 1

def banner():
    console.print(Fore.GREEN + """
    =============================================
         Argus - Advanced Domain Reputation Check
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    parsed = urlparse(f"http://{domain}")
    return parsed.netloc if parsed.netloc else parsed.path

def validate_domain(domain: str) -> bool:
    if len(domain) > 253:
        return False
    if domain.endswith("."):
        domain = domain[:-1]
    allowed = re.compile(r"^(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in domain.split("."))

def get_reputation_session():
    session = requests.Session()
    retries = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    return session

def check_domain_reputation(domain: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        'x-apikey': api_key
    }
    session = get_reputation_session()
    try:
        response = session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving domain reputation for {domain}: {e}")
        return {}

def display_reputation_report(domain: str, report: dict):
    data = report.get('data', {})
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    reputation = attributes.get('reputation', 'N/A')
    categories = attributes.get('categories', {})
    total_votes = attributes.get('total_votes', {})
    whois = attributes.get('whois', 'N/A')

    table = Table(title=f"Domain Reputation Report for {domain}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green", justify="left")

    table.add_row("Reputation", str(reputation))
    table.add_row("Harmless", str(last_analysis_stats.get('harmless', 0)))
    table.add_row("Malicious", str(last_analysis_stats.get('malicious', 0)))
    table.add_row("Suspicious", str(last_analysis_stats.get('suspicious', 0)))
    table.add_row("Undetected", str(last_analysis_stats.get('undetected', 0)))
    table.add_row("Timeout", str(last_analysis_stats.get('timeout', 0)))
    table.add_row("Categories", ', '.join(categories.values()) if categories else 'N/A')
    table.add_row("Total Votes", f"Harmless: {total_votes.get('harmless', 0)}, Malicious: {total_votes.get('malicious', 0)}")

    console.print(table)

def process_domain(domain, api_key):
    domain = clean_domain_input(domain)
    if not validate_domain(domain):
        console.print(Fore.RED + f"[!] Invalid domain format: {domain}")
        return

    console.print(Fore.WHITE + f"[*] Checking reputation for domain: {domain}")
    report = check_domain_reputation(domain, api_key)

    if report:
        display_reputation_report(domain, report)
    else:
        console.print(Fore.RED + f"[!] No reputation data available for {domain}.")

def main():
    banner()

    parser = argparse.ArgumentParser(description='Argus - Advanced Domain Reputation Check')
    parser.add_argument('domains', nargs='+', help='Domain(s) to check reputation')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--apikey', type=str, help='VirusTotal API Key')
    args = parser.parse_args()

    domains = args.domains
    threads = args.threads
    api_key = API_KEYS.get("VIRUSTOTAL_API_KEY")

    if not api_key:
        console.print(Fore.RED + "[!] VirusTotal API key not provided. Use --apikey or set the VIRUSTOTAL_API_KEY environment variable.")
        sys.exit(1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(process_domain, domain, api_key): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                future.result()
            except Exception as e:
                console.print(Fore.RED + f"[!] Error processing {domain}: {e}")

    console.print(Fore.CYAN + "[*] Domain Reputation Check completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
