import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url  


init(autoreset=True)
console = Console()

def banner():
    print(Fore.GREEN + """
    =============================================
              Argus - Crawl Rules Check
    =============================================
    """)

def get_robots_txt(url):
    try:
        response = requests.get(f"{url}/robots.txt", timeout=10)
        if response.status_code == 200:
            return response.text
        return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving robots.txt: {e}")
        return None

def display_robots_txt(content):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("robots.txt", style="green", justify="left")
    table.add_row(content if content else "No robots.txt found")
    console.print(table)

def main(target):
    banner()
    
    
    url = clean_url(target)

    console.print(Fore.WHITE + f"[*] Fetching robots.txt from: {url}")
    robots_txt = get_robots_txt(url)
    if robots_txt:
        display_robots_txt(robots_txt)
    else:
        console.print(Fore.RED + "[!] No robots.txt file found.")
    console.print(Fore.WHITE + "[*] Crawl rules analysis completed.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain, URL, or IP address.")
        sys.exit(1)
