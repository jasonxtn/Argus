import requests
import sys
import os
import re
from rich.console import Console
from rich.table import Table
from colorama import init

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input  
from config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

def banner():
    console.print("""
[green]
    =============================================
       Argus - Email Configuration Analysis
    =============================================
[/green]
    """)

# Function to validate email format using regex
def validate_email(email):
    pattern = re.compile(
        r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    )
    return pattern.match(email) is not None

def check_spf(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/spflookup/?q={domain}", timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return f"[!] SPF check failed with status code: {response.status_code}"
    except requests.RequestException as e:
        return f"[!] Error checking SPF: {e}"

def check_dkim(domain):
    # Placeholder for DKIM check, should ideally be implemented using DNS queries
    return f"[yellow]DKIM check for {domain} is not implemented yet.[/yellow]"

def check_dmarc(domain):
    # Placeholder for DMARC check, should ideally be implemented using DNS queries
    return f"[yellow]DMARC check for {domain} is not implemented yet.[/yellow]"

def display_email_config_report(domain, spf_result, dkim_result, dmarc_result):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Test", style="cyan", justify="left")
    table.add_column("Result", style="green", overflow="fold")

    table.add_row("SPF", spf_result)
    table.add_row("DKIM", dkim_result)
    table.add_row("DMARC", dmarc_result)

    console.print(table)

def main(email):
    banner()

    if not validate_email(email):
        console.print("[red][!] Invalid email format. Please check the email and try again.[/red]")
        return

    domain = clean_domain_input(email.split('@')[-1])

    console.print(f"[white][*] Checking email configuration for: {email} (Domain: {domain})[/white]")

    spf_result = check_spf(domain)
    dkim_result = check_dkim(domain)
    dmarc_result = check_dmarc(domain)

    display_email_config_report(domain, spf_result, dkim_result, dmarc_result)

    console.print("[white][*] Email configuration analysis completed.[/white]")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            email = sys.argv[1]
            main(email)
        except KeyboardInterrupt:
            console.print("\n[red][!] Process interrupted by user.[/red]")
            sys.exit(1)
    else:
        console.print("[red][!] No email provided. Please pass an email as an argument.[/red]")
        sys.exit(1)
