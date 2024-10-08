import sys
import os
import asyncio
import aiohttp
from aiohttp import ClientSession
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
from urllib.parse import urlparse
import re
import ssl
import socket


sys.path.append(os.path.join(os.path.dirname(__file__), 'Util'))
init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10
SHODAN_API_URL = "https://api.shodan.io/shodan/host/"
IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAX_CONCURRENT_REQUESTS = 5

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import API_KEYS
from utils.util import  resolve_to_ip  

SHODAN_API_KEY = API_KEYS.get("SHODAN_API_KEY")
if not SHODAN_API_KEY:
    console.print(Fore.RED + "[!] Shodan API key is not set. Please set it in config/settings.py.")
    sys.exit(1)

def banner():
    console.print(Fore.GREEN + """
=============================================
     Argus - Shodan Exposure Analyzer
=============================================
""")

def clean_domain(domain):
    domain = domain.strip()
    parsed = urlparse(domain)
    return parsed.netloc if parsed.netloc else domain

def validate_ip(ip):
    if not IP_PATTERN.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

async def fetch_shodan_data(session, ip, semaphore):
    async with semaphore:
        if not validate_ip(ip):
            console.print(Fore.RED + f"[!] Invalid IP address: {ip}")
            return {"input": ip, "ip": ip, "error": "Invalid IP"}

        url = f"{SHODAN_API_URL}{ip}"
        params = {"key": SHODAN_API_KEY}

        try:
            async with session.get(url, params=params, timeout=DEFAULT_TIMEOUT) as response:
                if response.status == 200:
                    data = await response.json()
                    return {"input": ip, "ip": ip, "data": data}
                errors = {
                    401: "Unauthorized. Check your Shodan API key.",
                    403: "Access Forbidden. Check your API key.",
                    404: "No data found.",
                    429: "Rate limit exceeded. Try again later."
                }
                error_msg = errors.get(response.status, f"Status code {response.status}")
                console.print(Fore.RED + f"[!] {ip}: {error_msg}")
                return {"input": ip, "ip": ip, "error": error_msg}
        except asyncio.TimeoutError:
            console.print(Fore.RED + f"[!] Timeout for IP: {ip}")
            return {"input": ip, "ip": ip, "error": "Timeout"}
        except Exception as e:
            console.print(Fore.RED + f"[!] Error for {ip}: {e}")
            return {"input": ip, "ip": ip, "error": str(e)}

def extract_statistics(data):
    return {
        "Open Ports": len(data.get('ports', [])),
        "Unique Services": list({f"{s.get('product', 'Unknown')} {s.get('version', '')}".strip()
                                 for s in data.get('data', []) if s.get('product') or s.get('version')} or ["Unknown"]),
        "Vulnerabilities": [vuln.strip('!') for vuln in data.get('vulns', [])] or ["None"],
        "Operating System": data.get('os', 'Unknown'),
        "Hostnames": ", ".join(data.get('hostnames', []) or ["None"]),
        "Location": f"{data.get('country_name', 'Unknown')}, {data.get('city', 'Unknown')}"
    }

def display_shodan_data(entry):
    if 'error' in entry:
        console.print(Fore.RED + f"[!] {entry['input']}: {entry['error']}")
        return

    data = entry['data']
    stats = extract_statistics(data)

    # General Info Table
    table = Table(title=f"Shodan Data for {entry['ip']}", box=box.ROUNDED)
    table.add_column("Field", style="cyan bold")
    table.add_column("Details", style="green bold")
    general_info = {
        "IP Address": entry['ip'],
        "Organization": data.get('org', 'Unknown'),
        "Operating System": stats["Operating System"],
        "Location": stats["Location"],
        "Hostnames": stats["Hostnames"]
    }
    for field, detail in general_info.items():
        table.add_row(field, detail)
    console.print(table)

    # Statistics Table
    stats_table = Table(title="Statistics", box=box.ROUNDED)
    stats_table.add_column("Metric", style="cyan bold")
    stats_table.add_column("Value", style="green bold")
    for key, value in stats.items():
        if isinstance(value, list):
            value = ", ".join(value)
        stats_table.add_row(key, str(value))
    console.print(stats_table)

    # Services Table
    services_table = Table(title="Open Ports and Services", box=box.ROUNDED)
    services_table.add_column("Port", style="cyan bold")
    services_table.add_column("Service", style="green bold")
    for port in data.get('ports', []):
        service = next((s for s in data.get('data', []) if s.get('port') == port), {})
        service_desc = " ".join(filter(None, [service.get('product'), service.get('version'), service.get('extrainfo')])).strip() or "Unknown"
        services_table.add_row(str(port), service_desc)
    console.print(services_table)

async def resolve_domain_async(domain):
    loop = asyncio.get_event_loop()
    ip = await loop.run_in_executor(None, resolve_to_ip, domain)
    if ip:
        return [ip]
    else:
        return []

async def main_async(inputs):
    banner()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    recon_results = []

    async with ClientSession() as session:
        tasks = []
        for input_item in inputs:
            clean_input = clean_domain(input_item)
            if validate_ip(clean_input):
                tasks.append(fetch_shodan_data(session, clean_input, semaphore))
            else:
                resolved_ips = await resolve_domain_async(clean_input)
                if resolved_ips:
                    for ip in resolved_ips:
                        tasks.append(fetch_shodan_data(session, ip, semaphore))
                else:
                    console.print(Fore.RED + f"[!] Could not resolve domain: {clean_input}")
                    recon_results.append({"input": clean_input, "ip": "-", "error": "Resolution failed"})

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
            task = progress.add_task("[cyan]Performing Shodan Recon...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                recon_results.append(result)
                display_shodan_data(result)
                progress.advance(task)

    console.print(Fore.CYAN + "[*] Shodan Recon completed.")

def main(inputs):
    try:
        asyncio.run(main_async(inputs))
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
    except Exception as e:
        console.print(Fore.RED + f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus - Shodan Exposure Analyzer")
    parser.add_argument('inputs', nargs='+', help='IP addresses or domains to analyze')
    args = parser.parse_args()
    main(args.inputs)
