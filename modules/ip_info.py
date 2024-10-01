import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init, Style

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DEFAULT_TIMEOUT  

init(autoreset=True)
console = Console()

def banner():
    console.print(f"""
{Fore.GREEN}=============================================
          Argus - IP Information
============================================={Style.RESET_ALL}
""")

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=DEFAULT_TIMEOUT)
        data = response.json()
        if response.status_code == 200 and data.get('status') == 'success':
            lat = data.get('lat')
            lon = data.get('lon')
            if lat and lon:
                data['map_link'] = f"https://www.google.com/maps?q={lat},{lon}"
            return data
        else:
            console.print(f"{Fore.RED}[!] Failed to retrieve IP information.{Style.RESET_ALL}")
            return None
    except requests.RequestException as e:
        console.print(f"{Fore.RED}[!] Error retrieving IP information: {e}{Style.RESET_ALL}")
        return None

def display_ip_info(ip_info):
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Key", style="white", justify="left", min_width=15)
    table.add_column("Value", style="white", justify="left", min_width=50)

    for key, value in ip_info.items():
        table.add_row(str(key), str(value))

    console.print(table)
    
    if 'map_link' in ip_info:
        console.print(f"\n{Fore.YELLOW}[+] View location on map: {ip_info['map_link']}{Style.RESET_ALL}")

def main(target):
    banner()
    console.print(f"{Fore.WHITE}[*] Fetching IP info for: {target}{Style.RESET_ALL}")

    ip = target  

    ip_info = get_ip_info(ip)

    if ip_info:
        display_ip_info(ip_info)
    else:
        console.print(f"{Fore.RED}[!] No IP information found.{Style.RESET_ALL}")

    console.print(f"{Fore.CYAN}[*] IP info retrieval completed.{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(f"{Fore.RED}[!] No target provided. Please pass a domain, URL, or IP address.{Style.RESET_ALL}")
        sys.exit(1)
