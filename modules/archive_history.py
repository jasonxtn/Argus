import sys
import os
import requests
from urllib.parse import urlparse
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

WAYBACK_CDX_API_URL = "http://web.archive.org/cdx/search/cdx"

def banner():
    console.print(f"""
{Fore.GREEN}=============================================
        Argus - Archive History Lookup
============================================={Style.RESET_ALL}
""")

def get_archive_history(domain):
    """Get the archive history for the given domain from the Wayback Machine."""
    try:
        console.print(f"{Fore.CYAN}[*] Retrieving archive history for domain: {domain}{Style.RESET_ALL}")
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "limit": 20,
            "filter": "statuscode:200",
            "fl": "timestamp,original",
            "collapse": "digest"
        }
        response = requests.get(WAYBACK_CDX_API_URL, params=params, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            return data
        else:
            console.print(f"{Fore.RED}[!] Failed to retrieve archive history: {response.status_code} - {response.reason}{Style.RESET_ALL}")
            return None
    except requests.RequestException as e:
        console.print(f"{Fore.RED}[!] Error retrieving archive history: {e}{Style.RESET_ALL}")
        return None

def display_archive_history(history, domain):
    """Display the archive history in a table format."""
    if not history or len(history) <= 1:
        console.print(f"{Fore.YELLOW}[!] No archive history found for {domain}.{Style.RESET_ALL}")
        return

    table = Table(show_header=True, header_style="bold white", style="white")
    table.add_column("Archived URL", style="white", justify="left", min_width=60)

    # Skip the header row in the returned data and display only available entries
    for record in history[1:]:
        timestamp, original_url = record[0], record[1]

        # Validate and complete the URL if needed
        parsed_url = urlparse(original_url)
        if not parsed_url.scheme:
            original_url = f"http://{original_url}"

        # Generate the archive link
        archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
        table.add_row(archive_url)

    console.print(table)
    console.print(f"\n{Fore.CYAN}[*] Archive history retrieval completed for {domain}.{Style.RESET_ALL}")

def archive_history_lookup(target):
    """Perform the archive history lookup process for the given target."""
    banner()
    domain = clean_domain_input(target)
    history = get_archive_history(domain)
    display_archive_history(history, domain)

def main(target):
    archive_history_lookup(target)

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
        console.print(f"{Fore.RED}[!] No target provided. Please pass a domain or URL.{Style.RESET_ALL}")
        sys.exit(1)
