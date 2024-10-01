import os
import sys
import ssl
import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from colorama import Fore, init

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
               Argus - SSL Chain Check
    =============================================
    """)

def get_ssl_chain(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_chain = ssock.getpeercert(True)
                certs = ssock.getpeercert()
                cert = ssl.DER_cert_to_PEM_cert(cert_chain)
                return cert, certs
    except (ssl.SSLError, socket.error, socket.timeout) as e:
        console.print(Fore.RED + f"[!] SSL/Socket error occurred: {e}")
        return None, None

def analyze_certificate(cert_data):
    analysis = {
        "Subject": cert_data.get("subject", []),
        "Issuer": cert_data.get("issuer", []),
        "Valid From": datetime.strptime(cert_data["notBefore"], "%b %d %H:%M:%S %Y %Z") if "notBefore" in cert_data else "N/A",
        "Valid Until": datetime.strptime(cert_data["notAfter"], "%b %d %H:%M:%S %Y %Z") if "notAfter" in cert_data else "N/A",
        "Serial Number": cert_data.get("serialNumber", "N/A"),
        "Version": cert_data.get("version", "N/A"),
        "Signature Algorithm": cert_data.get("signatureAlgorithm", "N/A"),
    }

    validity_period = (analysis["Valid Until"] - analysis["Valid From"]).days if analysis["Valid Until"] != "N/A" and analysis["Valid From"] != "N/A" else "N/A"
    days_left = (analysis["Valid Until"] - datetime.utcnow()).days if analysis["Valid Until"] != "N/A" else "N/A"
    analysis.update({"Validity Period (Days)": validity_period, "Days Until Expiry": days_left})

    return analysis

def display_ssl_chain(cert, cert_analysis):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Certificate Chain", style="cyan", justify="left")
    table.add_row(cert if cert else "No certificate data found")
    console.print(table)

    if cert_analysis:
        analysis_table = Table(title="SSL Certificate Analysis", show_header=True, header_style="bold magenta")
        analysis_table.add_column("Attribute", style="cyan", justify="left")
        analysis_table.add_column("Details", style="green", justify="left")

        for key, value in cert_analysis.items():
            if isinstance(value, list):
                value = ", ".join([f"{sub[0][0]}: {sub[0][1]}" for sub in value])  # Handle subject and issuer list
            elif isinstance(value, datetime):
                value = value.strftime("%Y-%m-%d %H:%M:%S")

            analysis_table.add_row(key, str(value))
        console.print(analysis_table)

def main(target):
    banner()
    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[*] Fetching SSL chain for: {domain}")
    cert, cert_data = get_ssl_chain(domain)

    if cert:
        cert_analysis = analyze_certificate(cert_data)
        display_ssl_chain(cert, cert_analysis)
    else:
        console.print(Fore.RED + "[!] SSL chain retrieval failed.")
    
    console.print(Fore.CYAN + "[*] SSL chain retrieval completed.")

if len(sys.argv) > 1:
    target = sys.argv[1]
    try:
        main(target)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
else:
    console.print(Fore.RED + "[!] No target provided. Please pass a domain.")
    sys.exit(1)
