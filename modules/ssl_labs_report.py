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
import time

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - Advanced SSL Labs Scanner
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    parsed_url = urlparse(domain)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return parsed_url.path

def fetch_ssl_labs_report(domain, use_cache=True):
    try:
        base_url = "https://api.ssllabs.com/api/v3/analyze"
        params = {
            'host': domain,
            'fromCache': 'on' if use_cache else 'off',
            'all': 'done'
        }
        response = requests.get(base_url, params=params, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            status = data.get('status')
            if status == 'READY':
                return data
            elif status in ['DNS', 'IN_PROGRESS', 'RUNNING']:
                # Poll until the analysis is ready
                console.print(Fore.YELLOW + f"[*] Analysis in progress for {domain}. Waiting for results...")
                while status != 'READY':
                    time.sleep(5)
                    response = requests.get(base_url, params=params, timeout=DEFAULT_TIMEOUT)
                    data = response.json()
                    status = data.get('status')
                return data
            else:
                console.print(Fore.RED + f"[!] Analysis failed for {domain}. Status: {status}")
                return None
        else:
            console.print(Fore.RED + f"[!] Error fetching SSL Labs report for {domain}: HTTP {response.status_code}")
            return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error fetching SSL Labs report for {domain}: {e}")
        return None

def display_ssl_labs_report(domain, data):
    endpoints = data.get("endpoints", [])
    if not endpoints:
        console.print(Fore.RED + f"[!] No endpoints found for {domain}.")
        return

    for endpoint in endpoints:
        ip_address = endpoint.get("ipAddress", "N/A")
        grade = endpoint.get("grade", "N/A")
        details = endpoint.get("details", {})
        protocols = details.get("protocols", [])
        suites_data = details.get("suites", {})
        suites = suites_data.get("list", []) if isinstance(suites_data, dict) else []

        server_signature = details.get("serverSignature", "N/A")
        ocsp_stapling = "Yes" if details.get("ocspStapling", False) else "No"

        hsts_policy_data = details.get("hstsPolicy", {})
        if isinstance(hsts_policy_data, dict):
            hsts_status = hsts_policy_data.get('status', 'N/A')
        else:
            hsts_status = 'N/A'

        vuln_beast = "Yes" if details.get("vulnBeast", False) else "No"
        poodle_tls = details.get("poodleTls", 0)
        heartbleed = "Yes" if details.get("heartbleed", False) else "No"
        supports_rc4 = "Yes" if details.get("supportsRc4", False) else "No"

        # Handle protocols list
        if isinstance(protocols, list):
            protocols_supported = ', '.join([f"{p.get('name', 'N/A')} {p.get('version', 'N/A')}" for p in protocols])
        else:
            protocols_supported = 'N/A'

        # Handle cipher suites list
        if isinstance(suites, list):
            cipher_suites = ', '.join([suite.get("name", "") for suite in suites])
        else:
            cipher_suites = 'N/A'

        table = Table(title=f"SSL Labs Report for {domain} [{ip_address}]", show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Field", style="cyan", justify="left")
        table.add_column("Details", style="green")

        table.add_row("Grade", grade)
        table.add_row("Protocols Supported", protocols_supported)
        table.add_row("Cipher Suites", cipher_suites)
        table.add_row("Server Signature", server_signature)
        table.add_row("OCSP Stapling", ocsp_stapling)
        table.add_row("HSTS Policy", hsts_status)
        table.add_row("Vulnerable to BEAST", vuln_beast)
        table.add_row("POODLE TLS", str(poodle_tls))
        table.add_row("Heartbleed Vulnerability", heartbleed)
        table.add_row("Supports RC4", supports_rc4)

        console.print(table)

def process_domain(domain, use_cache):
    domain = clean_domain_input(domain)
    console.print(Fore.WHITE + f"[*] Fetching SSL Labs report for: {domain}")
    ssl_labs_data = fetch_ssl_labs_report(domain, use_cache=use_cache)
    if ssl_labs_data:
        display_ssl_labs_report(domain, ssl_labs_data)
    else:
        console.print(Fore.RED + f"[!] No SSL Labs data found for {domain}.")

def main():
    banner()

    parser = argparse.ArgumentParser(description='Argus - Advanced SSL Labs Scanner')
    parser.add_argument('domains', nargs='+', help='Domain(s) to analyze')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--no-cache', action='store_true', help='Force a new analysis (do not use cached results)')
    args = parser.parse_args()

    domains = args.domains
    use_cache = not args.no_cache

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_domain, domain, use_cache): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                future.result()
            except Exception as e:
                console.print(Fore.RED + f"[!] Error processing {domain}: {e}")

    console.print(Fore.CYAN + "[*] SSL Labs analysis completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
