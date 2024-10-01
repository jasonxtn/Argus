import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DEFAULT_TIMEOUT  
from utils.util import validate_ip  


init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Server Location Detection
    =============================================
    """)

def get_server_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=DEFAULT_TIMEOUT)
        data = response.json()
        if data['status'] == 'success':
            return data
        return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving server location: {e}")
        return None

def display_server_location(location_data):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", justify="left")
    table.add_column("Details", style="green")

    for key, value in location_data.items():
        table.add_row(str(key), str(value))

    console.print(table)

def main(target):
    banner()

    if not validate_ip(target):
        console.print(Fore.RED + "[!] Invalid IP address. Please check the input and try again.")
        return

    console.print(Fore.WHITE + f"[*] Fetching server location for: {target}")
    location_info = get_server_location(target)
    if location_info:
        display_server_location(location_info)
    else:
        console.print(Fore.RED + "[!] No server location information found.")
    console.print(Fore.WHITE + "[*] Server location detection completed.")

if len(sys.argv) > 1:
    target = sys.argv[1]
    try:
        main(target)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
else:
    console.print(Fore.RED + "[!] No target provided. Please pass an IP address.")
    sys.exit(1)
