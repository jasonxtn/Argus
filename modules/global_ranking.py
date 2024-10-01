import sys
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
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
          Argus - Global Ranking Analysis
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    parsed_url = urlparse(domain)
    return parsed_url.netloc

def get_tranco_list_id():

    try:
        response = requests.get('https://tranco-list.eu/top-1m.csv.zip', allow_redirects=False, timeout=DEFAULT_TIMEOUT)
        if 'Location' in response.headers:
            redirect_url = response.headers['Location']
            list_id = redirect_url.split('/')[-2]
            return list_id
        else:
            console.print(Fore.RED + "[!] Unable to retrieve Tranco list ID.")
            return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving Tranco list ID: {e}")
        return None

def get_domain_rank(domain, list_id):

    try:
        url = f"https://tranco-list.eu/api/rank/{list_id}/{domain}"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            rank = data.get('rank')
            return rank
        elif response.status_code == 404:
            return None
        else:
            console.print(Fore.RED + f"[!] Error retrieving rank for {domain}: HTTP {response.status_code}")
            return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving rank for {domain}: {e}")
        return None

def display_global_ranking(domain, rank):
    table = Table(title=f"Global Ranking for {domain}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green")

    table.add_row("Global Rank", str(rank))

    console.print(table)

def main():
    banner()

    parser = argparse.ArgumentParser(description='Argus - Global Ranking Analysis')
    parser.add_argument('domains', nargs='+', help='Domain(s) to analyze')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()

    domains = args.domains

    console.print(Fore.WHITE + "[*] Retrieving current Tranco list ID...")
    list_id = get_tranco_list_id()
    if not list_id:
        console.print(Fore.RED + "[!] Failed to retrieve Tranco list ID.")
        sys.exit(1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_domain, domain, list_id): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                future.result()
            except Exception as e:
                console.print(Fore.RED + f"[!] Error processing {domain}: {e}")

    console.print(Fore.CYAN + "[*] Global ranking analysis completed.")

def process_domain(domain, list_id):
    domain = clean_domain_input(domain)
    console.print(Fore.WHITE + f"[*] Fetching global ranking for: {domain}")

    rank = get_domain_rank(domain, list_id)
    if rank:
        display_global_ranking(domain, rank)
    else:
        console.print(Fore.YELLOW + f"[!] {domain} is not ranked in the current Tranco list.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
