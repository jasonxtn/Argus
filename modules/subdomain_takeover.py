import sys
import asyncio
import aiohttp
import requests
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import Fore, init
import argparse
from urllib.parse import urlparse
import re
from datetime import datetime

init(autoreset=True)
console = Console()

TAKEOVER_INDICATORS = {
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist."],
    "GitHub Pages": ["There isn't a GitHub Pages site here."],
    "Azure Blob Storage": ["BlobNotFound", "No blob exists with this name."],
    "Heroku": ["No such app", "Could not find that application."],
    "Google Cloud Storage": ["BucketNotFound", "NoSuchBucket"],
    "DigitalOcean Spaces": ["NoSuchBucket"],
    "Firebase Hosting": ["There isn't a Firebase Hosting site here."]
}

IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + """
    =============================================
        Argus - Advanced Subdomain Takeover Detection
    =============================================
    """)

def resolve_subdomains(domain):
    console.print(Fore.WHITE + f"[*] Fetching subdomains for {domain} from crt.sh...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                subdomains.update(name.split('\n'))
            subdomains = sorted(subdomains)
            console.print(Fore.GREEN + f"[+] Found {len(subdomains)} subdomains for {domain}.")
            return subdomains
        console.print(Fore.RED + f"[!] Failed to retrieve subdomains for {domain} from crt.sh.")
        return []
    except requests.RequestException:
        console.print(Fore.RED + f"[!] Error fetching subdomains for {domain}.")
        return []

def validate_ip(ip):
    if not IP_PATTERN.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

async def check_subdomain_takeover(session, subdomain, semaphore):
    async with semaphore:
        for protocol in ["http", "https"]:
            console.print(Fore.WHITE + f"[*] Checking {subdomain} ({protocol.upper()})...")
            url = f"{protocol}://{subdomain}"
            try:
                async with session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True) as response:
                    text = await response.text()
                    for service, indicators in TAKEOVER_INDICATORS.items():
                        for indicator in indicators:
                            if indicator in text:
                                console.print(Fore.RED + f"[!] Vulnerable: {subdomain} ({protocol.upper()}) - Service: {service}")
                                return subdomain
                    console.print(Fore.GREEN + f"[+] Safe: {subdomain} ({protocol.upper()})")
            except asyncio.TimeoutError:
                console.print(Fore.RED + f"[!] Timeout: {subdomain} ({protocol.upper()})")
            except aiohttp.ClientError:
                console.print(Fore.RED + f"[!] Error accessing: {subdomain} ({protocol.upper()})")
    return None

def display_vulnerable_subdomains(vulnerable_subdomains):
    if not vulnerable_subdomains:
        console.print(Fore.GREEN + "[+] No vulnerable subdomains found.")
        return
    table = Table(title="Vulnerable Subdomains", box=box.ROUNDED)
    table.add_column("Subdomain", style="cyan", justify="left")
    table.add_column("Protocol", style="red", justify="left")
    for sub, proto in vulnerable_subdomains:
        table.add_row(sub, proto)
    console.print(table)

async def main_async(inputs):
    semaphore = asyncio.Semaphore(20)
    vulnerable_subdomains = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for input_item in inputs:
            parsed = urlparse(f"http://{input_item}")
            domain = parsed.netloc if parsed.netloc else parsed.path
            if validate_ip(domain):
                tasks.append(check_subdomain_takeover(session, domain, semaphore))
            else:
                subdomains = resolve_subdomains(domain)
                if not subdomains:
                    console.print(Fore.RED + f"[!] No subdomains found for {domain}.")
                    continue
                for sub in subdomains:
                    tasks.append(check_subdomain_takeover(session, sub, semaphore))
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                vulnerable_subdomains.append(result)
    display_vulnerable_subdomains(vulnerable_subdomains)
    console.print(Fore.CYAN + "[*] Subdomain takeover check completed.")

def main(inputs):
    banner()
    asyncio.run(main_async(inputs))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus - Advanced Subdomain Takeover Detection Tool")
    parser.add_argument(
        'inputs',
        metavar='INPUT',
        type=str,
        nargs='+',
        help='One or more subdomains or domains to check for takeover'
    )
    args = parser.parse_args()
    try:
        main(args.inputs)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
    except Exception as e:
        console.print(Fore.RED + f"\n[!] An unexpected error occurred: {e}")
        sys.exit(1)
