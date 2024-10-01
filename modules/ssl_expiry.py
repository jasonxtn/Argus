import sys
import ssl
import socket
import re
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import Fore, init
import argparse
import concurrent.futures

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + """
    =============================================
               Argus - Advanced SSL Expiry Check 
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    parsed = urlparse(f"http://{domain}")
    return parsed.netloc if parsed.netloc else parsed.path

def validate_domain(domain: str) -> bool:
    if len(domain) > 253:
        return False
    if domain.endswith("."):
        domain = domain[:-1]
    allowed = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Z\d-]{1,63}(?<!-)(\.(?!-)[A-Z\d-]{1,63}(?<!-))*\.?$",
        re.IGNORECASE
    )
    return allowed.match(domain) is not None

def ssl_expiry_check(domain: str) -> tuple:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                days_left = (expiry_date - datetime.utcnow()).days
                return expiry_date, days_left, cert
    except Exception as e:
        console.print(Fore.RED + f"[!] Error during SSL expiry check for {domain}: {e}")
        return None, None, None

def display_ssl_expiry(domain: str, expiry_date: datetime, days_left: int, cert: dict):
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("SSL Expiry Details", style="cyan", justify="left")
    table.add_column("Value", style="green")
    table.add_row("Domain", domain)
    table.add_row("Expiry Date", expiry_date.strftime("%Y-%m-%d %H:%M:%S") if expiry_date else "N/A")
    table.add_row("Days Left", str(days_left) if days_left is not None else "N/A")
    console.print(table)
    
    if cert:
        analysis_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        analysis_table.add_column("Attribute", style="cyan", justify="left")
        analysis_table.add_column("Details", style="green", justify="left")
        
        subject = ", ".join(f"{name}={value}" for sub in cert.get("subject", []) for (name, value) in sub)
        issuer = ", ".join(f"{name}={value}" for sub in cert.get("issuer", []) for (name, value) in sub)
        valid_from = cert.get("notBefore", "N/A")
        valid_until = cert.get("notAfter", "N/A")
        serial_number = cert.get("serialNumber", "N/A")
        version = cert.get("version", "N/A")
        signature_algorithm = cert.get("signatureAlgorithm", "N/A")
        
        try:
            valid_from_date = datetime.strptime(valid_from, '%b %d %H:%M:%S %Y GMT')
            valid_until_date = datetime.strptime(valid_until, '%b %d %H:%M:%S %Y GMT')
            validity_period = (valid_until_date - valid_from_date).days
            days_until_expiry = days_left
        except:
            validity_period = "N/A"
            days_until_expiry = "N/A"
        
        analysis_table.add_row("Subject", subject)
        analysis_table.add_row("Issuer", issuer)
        analysis_table.add_row("Valid From", valid_from)
        analysis_table.add_row("Valid Until", valid_until)
        analysis_table.add_row("Validity Period (Days)", str(validity_period))
        analysis_table.add_row("Days Until Expiry", str(days_until_expiry))
        analysis_table.add_row("Serial Number", serial_number)
        analysis_table.add_row("Version", str(version))
        analysis_table.add_row("Signature Algorithm", signature_algorithm)
        
        console.print(analysis_table)

def generate_stats(results: list):
    total = len(results)
    scanned = sum(1 for r in results if r['expiry_date'] is not None)
    failed = total - scanned
    expired = sum(1 for r in results if r['days_left'] is not None and r['days_left'] < 0)
    expiring_soon = sum(1 for r in results if r['days_left'] is not None and 0 <= r['days_left'] <= 30)
    healthy = sum(1 for r in results if r['days_left'] is not None and r['days_left'] > 30)
    
    average_days_left = sum(r['days_left'] for r in results if r['days_left'] is not None) / scanned if scanned else 0
    
    table = Table(title="SSL Expiry Statistics", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green", justify="left")
    
    table.add_row("Total Domains Checked", str(total))
    table.add_row("Successfully Scanned", str(scanned))
    table.add_row("Failed to Scan", str(failed))
    table.add_row("Expired Certificates", str(expired))
    table.add_row("Expiring Within 30 Days", str(expiring_soon))
    table.add_row("Healthy Certificates", str(healthy))
    table.add_row("Average Days Until Expiry", f"{average_days_left:.2f}")
    
    console.print(table)

def ssl_expiry(domain: str):
    if not validate_domain(domain):
        console.print(Fore.RED + f"[!] Invalid domain format: {domain}")
        return {
            "domain": domain,
            "expiry_date": None,
            "days_left": None
        }
    
    expiry_date, days_left, cert = ssl_expiry_check(domain)
    
    if expiry_date:
        display_ssl_expiry(domain, expiry_date, days_left, cert)
        return {
            "domain": domain,
            "expiry_date": expiry_date,
            "days_left": days_left
        }
    else:
        console.print(Fore.RED + f"[!] No SSL certificate found for domain: {domain}")
        return {
            "domain": domain,
            "expiry_date": None,
            "days_left": None
        }

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Argus - Advanced SSL Expiry Check')
    parser.add_argument('domains', nargs='+', help='Domain(s) to check SSL expiry')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()
    
    domains = args.domains
    threads = args.threads
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {executor.submit(ssl_expiry, domain): domain for domain in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                console.print(Fore.RED + f"[!] Error processing {domain}: {e}")
                results.append({
                    "domain": domain,
                    "expiry_date": None,
                    "days_left": None
                })
    generate_stats(results)
    console.print(Fore.CYAN + "[*] SSL expiry check completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Script interrupted by user.")
        sys.exit(1)
