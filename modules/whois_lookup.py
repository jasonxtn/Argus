import sys
import os
import subprocess
from rich.console import Console
from rich.table import Table
from colorama import Fore, init, Style

# Add parent directory to sys.path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input

# Initialize colorama
init(autoreset=True)
console = Console()

def banner():
    console.print(f"""
{Fore.GREEN}=============================================
        Argus - WHOIS Lookup Module
============================================={Style.RESET_ALL}
""")

def perform_whois_lookup(domain):
    """Perform WHOIS lookup for the given domain using subprocess."""
    try:
        console.print(f"{Fore.CYAN}[*] Performing WHOIS lookup for domain: {domain}{Style.RESET_ALL}")
        result = subprocess.run(["whois", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        
        if result.returncode != 0:
            console.print(f"{Fore.RED}[!] Failed to perform WHOIS lookup for {domain}: {result.stderr.strip()}{Style.RESET_ALL}")
            return None
        
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        console.print(f"{Fore.RED}[!] WHOIS lookup timed out for {domain}{Style.RESET_ALL}")
        return None
    except FileNotFoundError:
        console.print(f"{Fore.RED}[!] 'whois' command not found. Please ensure it is installed on your system.{Style.RESET_ALL}")
        return None
    except Exception as e:
        console.print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
        return None

def display_whois_info(whois_data):
    """Display the WHOIS information in a table format."""
    if not whois_data:
        console.print(f"{Fore.YELLOW}[!] No WHOIS information found.{Style.RESET_ALL}")
        return

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Key", style="white", justify="left", min_width=20)
    table.add_column("Value", style="white", justify="left", min_width=50)

    # Parsing the WHOIS data and adding it to the table
    for line in whois_data.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            table.add_row(key.strip(), value.strip())

    console.print(table)
    console.print(f"\n{Fore.CYAN}[*] WHOIS lookup completed.{Style.RESET_ALL}")

def whois_lookup(target):
    """Perform the WHOIS lookup process for the given target."""
    banner()
    domain = clean_domain_input(target)
    whois_data = perform_whois_lookup(domain)
    display_whois_info(whois_data)

def main(target):
    whois_lookup(target)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
            sys.exit(0)  # Explicitly exit with code 0
        except KeyboardInterrupt:
            console.print(f"\n{Fore.RED}[!] Script interrupted by user.{Style.RESET_ALL}")
            sys.exit(0)  # Exit with code 0 to prevent errors in argus.py
        except Exception as e:
            console.print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
            sys.exit(1)  # Exit with code 1 to indicate an error
    else:
        console.print(f"{Fore.RED}[!] No target provided. Please pass a domain or IP address.{Style.RESET_ALL}")
        sys.exit(1)
