import sys,os
import asyncio
import aiohttp
import requests
from aiohttp import ClientSession
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
from urllib.parse import urlparse
import re
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import API_KEYS

init(autoreset=True)
console = Console()

# Set default timeout
DEFAULT_TIMEOUT = 10

SHODAN_API_KEY = API_KEYS.get("VIRUSTOTAL_API_KEY")
if not SHODAN_API_KEY:
    console.print(Fore.RED + "[!] Shodan API key is not set. Please set it in the script.")
    sys.exit(1)

SHODAN_API_URL = "https://api.shodan.io/shodan/host/"

IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

MAX_CONCURRENT_REQUESTS = 5

def banner():
    console.print(Fore.GREEN + """
=============================================
     Argus - Shodan Exposure Analyzer
=============================================
""")

def clean_domain(domain):
    domain = domain.strip()
    parsed_url = urlparse(domain)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return domain

def resolve_to_ip(domain):
    try:
        response = requests.get(f'https://dns.google/resolve?name={domain}&type=A', timeout=DEFAULT_TIMEOUT)
        data = response.json()
        ips = [answer['data'] for answer in data.get('Answer', []) if answer.get('type') == 1]
        return ips
    except Exception as e:
        console.print(Fore.RED + f"[!] Error resolving {domain}: {e}")
        return []

def validate_ip(ip):
    if not IP_PATTERN.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

async def fetch_shodan_data(session, ip, semaphore):
    async with semaphore:
        if not validate_ip(ip):
            console.print(Fore.RED + f"[!] Invalid IP address: {ip}")
            return {"input": ip, "ip": ip, "error": "Invalid IP"}
        url = f"{SHODAN_API_URL}{ip}"
        params = {
            "key": SHODAN_API_KEY
        }
        try:
            async with session.get(url, params=params, timeout=DEFAULT_TIMEOUT) as response:
                if response.status == 200:
                    data = await response.json()
                    return {"input": ip, "ip": ip, "data": data}
                elif response.status == 403:
                    console.print(Fore.RED + f"[!] {ip}: Access Forbidden. Check API key.")
                    return {"input": ip, "ip": ip, "error": "Access Forbidden"}
                elif response.status == 404:
                    console.print(Fore.YELLOW + f"[!] No data found for IP: {ip}")
                    return {"input": ip, "ip": ip, "error": "No data found"}
                elif response.status == 401:
                    console.print(Fore.RED + "[!] Unauthorized. Check your Shodan API key.")
                    return {"input": ip, "ip": ip, "error": "Unauthorized"}
                elif response.status == 429:
                    console.print(Fore.RED + "[!] Rate limit exceeded. Try again later.")
                    return {"input": ip, "ip": ip, "error": "Rate limit exceeded"}
                else:
                    console.print(Fore.RED + f"[!] Shodan API returned status code {response.status} for IP: {ip}")
                    return {"input": ip, "ip": ip, "error": f"Status code {response.status}"}
        except asyncio.TimeoutError:
            console.print(Fore.RED + f"[!] Timeout while retrieving data for IP: {ip}")
            return {"input": ip, "ip": ip, "error": "Timeout"}
        except Exception as e:
            console.print(Fore.RED + f"[!] Error retrieving Shodan data for IP {ip}: {e}")
            return {"input": ip, "ip": ip, "error": str(e)}

def extract_statistics(data):
    stats = {}
    stats['Number of Open Ports'] = len(data.get('ports', []))
    services = [f"{service.get('product', 'Unknown')} {service.get('version', '')}".strip() for service in data.get('data', [])]
    services = [s for s in services if s]
    stats['Unique Services'] = list(set(services)) if services else ["Unknown"]
    vulnerabilities = [vuln.replace('!', '') for vuln in data.get('vulns', [])]
    stats['Vulnerabilities'] = vulnerabilities if vulnerabilities else ["None"]
    stats['Operating System'] = data.get('os', 'Unknown')
    stats['Hostnames'] = data.get('hostnames', ['None'])
    location = data.get('location', {})
    stats['Location'] = f"{location.get('country_name', 'Unknown')}, {location.get('city', 'Unknown')}"
    return stats

def display_shodan_data(entry):
    if 'error' in entry:
        console.print(Fore.RED + f"[!] {entry['input']}: {entry['error']}")
        return
    ip = entry['ip']
    data = entry['data']
    general_info = {
        "IP Address": ip,
        "Organization": data.get('org', 'Unknown'),
        "Operating System": data.get('os', 'Unknown'),
        "Location": f"{data.get('country_name', 'Unknown')}, {data.get('city', 'Unknown')}",
        "Hostnames": ", ".join(data.get('hostnames', ['None']))
    }
    stats = extract_statistics(data)
    table_general = Table(title=f"General Information for {ip}", box=box.ROUNDED)
    table_general.add_column("Field", style="bold cyan", justify="left")
    table_general.add_column("Details", style="bold green", justify="left")
    for key, value in general_info.items():
        table_general.add_row(key, value)
    table_stats = Table(title="Statistics", box=box.ROUNDED)
    table_stats.add_column("Metric", style="bold cyan", justify="left")
    table_stats.add_column("Value", style="bold green", justify="left")
    for key, value in stats.items():
        if isinstance(value, list):
            value = ", ".join(value)
        table_stats.add_row(key, value)
    table_services = Table(title="Open Ports and Services", box=box.ROUNDED)
    table_services.add_column("Port", style="bold cyan", justify="left")
    table_services.add_column("Service", style="bold green", justify="left")
    for port in data.get('ports', []):
        service_info = next((s for s in data.get('data', []) if s.get('port') == port), {})
        product = service_info.get('product', 'Unknown')
        version = service_info.get('version', '')
        extrainfo = service_info.get('extrainfo', '')
        service = " ".join([product, version, extrainfo]).strip()
        table_services.add_row(str(port), service)
    console.print(table_general)
    console.print(table_stats)
    console.print(table_services)

async def main_async(inputs):
    banner()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    async with ClientSession() as session:
        tasks = []
        for input_item in inputs:
            input_item = clean_domain(input_item)
            if validate_ip(input_item):
                tasks.append(fetch_shodan_data(session, input_item, semaphore))
            else:
                resolved_ips = resolve_to_ip(input_item)
                if resolved_ips:
                    for ip in resolved_ips:
                        tasks.append(fetch_shodan_data(session, ip, semaphore))
                else:
                    console.print(Fore.RED + f"[!] Unable to resolve domain: {input_item}")
                    tasks.append({"input": input_item, "ip": "-", "error": "Domain resolution failed"})
        recon_results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Performing Shodan Recon...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                recon_results.append(result)
                display_shodan_data(result)
                progress.advance(task)
    console.print(Fore.CYAN + "[*] Shodan Recon completed.")

def main(inputs):
    asyncio.run(main_async(inputs))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus - Shodan Exposure Analyzer")
    parser.add_argument(
        'inputs',
        metavar='INPUT',
        type=str,
        nargs='+',
        help='One or more IP addresses or domains to perform Shodan Recon'
    )
    args = parser.parse_args()
    try:
        main(args.inputs)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
