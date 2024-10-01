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
             Argus - Domain Information
    =============================================
    """)

def get_domain_info(domain):
    try:
        api_url = f"https://api.domainsdb.info/v1/domains/search?domain={domain}&zone=com"
        response = requests.get(api_url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            return response.json()
        console.print(Fore.RED + f"[!] Error: Received status code {response.status_code}.")
        return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving domain information: {e}")
        return None

def display_domain_info(info):
    if info.get('domains'):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Field", style="cyan", justify="left")
        table.add_column("Details", style="green")

        for domain in info['domains']:
            for key, value in domain.items():
                table.add_row(str(key), str(value))

        console.print(table)
    else:
        console.print(Fore.RED + "[!] No domain information found.")

def main(target):
    banner()

    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[*] Fetching domain information for: {domain}")
    domain_info = get_domain_info(domain)
    
    if domain_info:
        display_domain_info(domain_info)
    else:
        console.print(Fore.RED + "[!] No domain information found.")
    
    console.print(Fore.WHITE + "[*] Domain information retrieval completed.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain.")
        sys.exit(1)
