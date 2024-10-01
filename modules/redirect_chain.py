import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url  
from config.settings import DEFAULT_TIMEOUT  


init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - Redirect Chain Tracking
    =============================================
    """)

def get_redirect_chain(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=DEFAULT_TIMEOUT)
        return response.history
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving redirect chain: {e}")
        return None

def display_redirect_chain(redirect_history):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Redirect URL", style="cyan", justify="left")
    table.add_column("Status Code", style="green")

    for response in redirect_history:
        table.add_row(response.url, str(response.status_code))

    console.print(table)

def main(target):
    banner()

    url = clean_url(target)  
    console.print(Fore.WHITE + f"[*] Fetching redirect chain for: {url}")
    
    redirect_history = get_redirect_chain(url)
    
    if redirect_history:
        display_redirect_chain(redirect_history)
    else:
        console.print(Fore.RED + "[!] No redirect chain found.")
    
    console.print(Fore.WHITE + "[*] Redirect chain tracking completed.")

if len(sys.argv) > 1:
    target = sys.argv[1]
    try:
        main(target)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
else:
    console.print(Fore.RED + "[!] No target provided. Please pass a URL.")
    sys.exit(1)
