import os
import sys
import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url, validate_url
from config.settings import API_KEYS

# Initialize Colorama and Console
init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - VirusTotal Scan Module
    =============================================
    """)

async def scan_with_virustotal(session, url, api_key):
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {
        "apikey": api_key,
        "resource": url,
    }
    try:
        async with session.get(api_url, params=params, timeout=15) as response:
            if response.status == 200:
                return await response.json()
            else:
                console.print(Fore.RED + f"[!] Error: Received status code {response.status} for URL: {url}")
                return None
    except asyncio.TimeoutError:
        console.print(Fore.RED + f"[!] Timeout while scanning URL: {url}")
        return None
    except aiohttp.ClientError as e:
        console.print(Fore.RED + f"[!] Client error while scanning URL {url}: {e}")
        return None

def display_virustotal_scan(scan_data, url):
    if not scan_data:
        console.print(Fore.RED + f"[!] No data to display for URL: {url}")
        return
    
    response_code = scan_data.get("response_code")
    if response_code == 0:
        console.print(Fore.YELLOW + f"[!] URL {url} has not been scanned yet.")
        return
    elif response_code == -2:
        console.print(Fore.YELLOW + f"[!] URL {url} is queued for scanning.")
        return
    elif response_code == 1:
        positives = scan_data.get("positives", 0)
        total = scan_data.get("total", 0)
        scan_date = scan_data.get("scan_date", "N/A")
        verbose_msg = scan_data.get("verbose_msg", "")
        
        console.print(Fore.WHITE + f"[*] Scan Date: {scan_date}")
        console.print(Fore.WHITE + f"[*] Detected by {positives} out of {total} engines.")
        console.print(Fore.WHITE + f"[*] Scan Status: {verbose_msg}")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Scan Engine", style="cyan", justify="left")
        table.add_column("Detected", style="green", justify="left")
        table.add_column("Result", style="yellow", justify="left")
        
        scans = scan_data.get("scans", {})
        for engine, result in scans.items():
            detected = "Yes" if result.get("detected") else "No"
            result_detail = result.get("result", "N/A")
            table.add_row(engine, detected, result_detail)
        
        console.print(table)

def generate_stats(all_scan_data):
    total_urls = len(all_scan_data)
    scanned_urls = sum(1 for data in all_scan_data if data and data.get("response_code") == 1)
    queued_urls = sum(1 for data in all_scan_data if data and data.get("response_code") == -2)
    not_scanned_urls = sum(1 for data in all_scan_data if data and data.get("response_code") == 0)
    total_positives = sum(data.get("positives", 0) for data in all_scan_data if data and data.get("response_code") == 1)
    total_engines = sum(data.get("total", 0) for data in all_scan_data if data and data.get("response_code") == 1)
    
    detection_percentage = (total_positives / total_engines * 100) if total_engines else 0
    
    table = Table(title="VirusTotal Scan Statistics", box="ROUNDED")
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green", justify="left")
    
    table.add_row("Total URLs Scanned", str(total_urls))
    table.add_row("Successfully Scanned", str(scanned_urls))
    table.add_row("Queued for Scanning", str(queued_urls))
    table.add_row("Not Scanned", str(not_scanned_urls))
    table.add_row("Total Positives", str(total_positives))
    table.add_row("Total Engines", str(total_engines))
    table.add_row("Detection Percentage", f"{detection_percentage:.2f}%")
    
    console.print(table)

async def run_scans(targets, api_key):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in targets:
            console.print(Fore.WHITE + f"[*] Scanning URL: {url}")
            tasks.append(scan_with_virustotal(session, url, api_key))
        
        # Run all scans concurrently
        scan_data = await asyncio.gather(*tasks)

        # Process results
        for url, data in zip(targets, scan_data):
            console.print(Fore.WHITE + f"[*] Processing results for: {url}")
            display_virustotal_scan(data, url)

        generate_stats(scan_data)

def main(targets):
    banner()
    api_key = API_KEYS.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        console.print(Fore.RED + "[!] VirusTotal API key is not set. Please set it in config/settings.py or as an environment variable.")
        sys.exit(1)
    
    cleaned_targets = []
    for target in targets:
        cleaned = clean_url(target)
        if validate_url(cleaned):
            cleaned_targets.append(cleaned)
        else:
            console.print(Fore.RED + f"[!] Invalid URL format: {target}")
    
    if not cleaned_targets:
        console.print(Fore.RED + "[!] No valid URLs to scan.")
        sys.exit(1)

    console.print(Fore.WHITE + f"[*] Initiating VirusTotal scans for {len(cleaned_targets)} URL(s)...")
    
    # Run asynchronous scanning
    asyncio.run(run_scans(cleaned_targets, api_key))
    console.print(Fore.CYAN + "[*] VirusTotal scan completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            main(sys.argv[1:])
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
        except Exception as e:
            console.print(Fore.RED + f"\n[!] An unexpected error occurred: {e}")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass one or more URLs.")
        sys.exit(1)
