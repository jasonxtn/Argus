import sys
import socket
import requests
import re
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

# Initialize Colorama and Rich Console
init(autoreset=True)
console = Console()

# Set default timeout for requests
DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + """
    =============================================
              Argus - Server Information
    =============================================
    """)

def validate_ip(ip):
    # Simple regex to check if IP address is valid
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(ip):
        # Check if each octet is between 0 and 255
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

def resolve_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_server_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving server information: {e}")
        return None

def display_server_info(info):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", justify="left")
    table.add_column("Details", style="green")

    for key, value in info.items():
        table.add_row(str(key), str(value))

    console.print(table)

def main(target):
    banner()
    
    # Resolve domain to IP if target is not a valid IP address
    if not validate_ip(target):
        console.print(Fore.YELLOW + f"[!] '{target}' is not a valid IP address, attempting to resolve to an IP...")
        ip = resolve_to_ip(target)
        if ip:
            console.print(Fore.WHITE + f"[+] Resolved domain '{target}' to IP: {ip}")
            target = ip
        else:
            console.print(Fore.RED + "[!] Unable to resolve the domain to an IP address. Please check the input and try again.")
            return
    
    console.print(Fore.WHITE + f"[*] Fetching server information for: {target}")
    server_info = get_server_info(target)
    if server_info and server_info.get('status') == 'success':
        display_server_info(server_info)
    else:
        console.print(Fore.RED + "[!] No server information found.")
    console.print(Fore.WHITE + "[*] Server information retrieval completed.")

if len(sys.argv) > 1:
    target = sys.argv[1]
    try:
        main(target)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
else:
    console.print(Fore.RED + "[!] No target provided. Please pass an IP address or domain.")
    sys.exit(1)
