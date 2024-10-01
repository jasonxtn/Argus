import os
import sys
import time
import subprocess
import random
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.progress import Progress
from rich.spinner import Spinner
from rich.box import SIMPLE_HEAVY
from colorama import Fore, init
from utils.report_generator import generate_report
from utils.util import check_api_configured

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from config import settings

# Initialize Colorama and Rich Console
init(autoreset=True)
console = Console()

# Check Python version compatibility
if sys.version_info < (3, 0):
    print("This script requires Python 3.")
    sys.exit(1)

# Script metadata
VERSION = "1.0"
AUTHOR = "Jason13"

# Define tools with their attributes
tools = [
    # Network & Infrastructure (1-18)
    {'number': '1', 'name': 'Associated Hosts', 'script': 'associated_hosts.py', 'section': 'Network & Infrastructure'},
    {'number': '2', 'name': 'DNS Over HTTPS', 'script': 'dns_over_https.py', 'section': 'Network & Infrastructure'},
    {'number': '3', 'name': 'DNS Records', 'script': 'dns_records.py', 'section': 'Network & Infrastructure'},
    {'number': '4', 'name': 'DNSSEC Check', 'script': 'dnssec.py', 'section': 'Network & Infrastructure'},
    {'number': '5', 'name': 'Domain Info', 'script': 'domain_info.py', 'section': 'Network & Infrastructure'},
    {'number': '6', 'name': 'Domain Reputation Check', 'script': 'domain_reputation_check.py', 'section': 'Network & Infrastructure'},
    {'number': '7', 'name': 'IP Info', 'script': 'ip_info.py', 'section': 'Network & Infrastructure'},
    {'number': '8', 'name': 'Open Ports Scan', 'script': 'open_ports.py', 'section': 'Network & Infrastructure'},
    {'number': '9', 'name': 'Server Info', 'script': 'server_info.py', 'section': 'Network & Infrastructure'},
    {'number': '10', 'name': 'Server Location', 'script': 'server_location.py', 'section': 'Network & Infrastructure'},
    {'number': '11', 'name': 'SSL Chain Analysis', 'script': 'ssl_chain.py', 'section': 'Network & Infrastructure'},
    {'number': '12', 'name': 'SSL Expiry Alert', 'script': 'ssl_expiry.py', 'section': 'Network & Infrastructure'},
    {'number': '13', 'name': 'TLS Cipher Suites', 'script': 'tls_cipher_suites.py', 'section': 'Network & Infrastructure'},
    {'number': '14', 'name': 'TLS Handshake Simulation', 'script': 'tls_handshake.py', 'section': 'Network & Infrastructure'},
    {'number': '15', 'name': 'Traceroute', 'script': 'traceroute.py', 'section': 'Network & Infrastructure'},
    {'number': '16', 'name': 'TXT Records', 'script': 'txt_records.py', 'section': 'Network & Infrastructure'},
    {'number': '17', 'name': 'WHOIS Lookup', 'script': 'whois_lookup.py', 'section': 'Network & Infrastructure'},
    {'number': '18', 'name': 'Zone Transfer', 'script': 'zonetransfer.py', 'section': 'Network & Infrastructure'},

    # Web Application Analysis (19-34)
    {'number': '19', 'name': 'Archive History', 'script': 'archive_history.py', 'section': 'Web Application Analysis'},
    {'number': '20', 'name': 'Broken Links Detection', 'script': 'broken_links.py', 'section': 'Web Application Analysis'},
    {'number': '21', 'name': 'Carbon Footprint', 'script': 'carbon_footprint.py', 'section': 'Web Application Analysis'},
    {'number': '22', 'name': 'CMS Detection', 'script': 'cms_detection.py', 'section': 'Web Application Analysis'},
    {'number': '23', 'name': 'Cookies Analyzer', 'script': 'cookies.py', 'section': 'Web Application Analysis'},
    {'number': '24', 'name': 'Content Discovery', 'script': 'content_discovery.py', 'section': 'Web Application Analysis'},
    {'number': '25', 'name': 'Crawler', 'script': 'crawler.py', 'section': 'Web Application Analysis'},
    {'number': '26', 'name': 'Robots.txt Analyzer', 'script': 'crawl_rules.py', 'section': 'Web Application Analysis'},
    {'number': '27', 'name': 'Directory Finder', 'script': 'directory_finder.py', 'section': 'Web Application Analysis'},
    {'number': '28', 'name': 'Performance Monitoring', 'script': 'performance_monitoring.py', 'section': 'Web Application Analysis'},
    {'number': '29', 'name': 'Quality Metrics', 'script': 'quality_metrics.py', 'section': 'Web Application Analysis'},
    {'number': '30', 'name': 'Redirect Chain', 'script': 'redirect_chain.py', 'section': 'Web Application Analysis'},
    {'number': '31', 'name': 'Sitemap Parsing', 'script': 'sitemap.py', 'section': 'Web Application Analysis'},
    {'number': '32', 'name': 'Social Media Presence Scan', 'script': 'social_media.py', 'section': 'Web Application Analysis'},
    {'number': '33', 'name': 'Technology Stack Detection', 'script': 'technology_stack.py', 'section': 'Web Application Analysis'},
    {'number': '34', 'name': 'Third-Party Integrations', 'script': 'third_party_integrations.py', 'section': 'Web Application Analysis'},

    # Security & Threat Intelligence (35-51)
    {'number': '35', 'name': 'Censys Reconnaissance', 'script': 'censys.py', 'section': 'Security & Threat Intelligence'},
    {'number': '36', 'name': 'Certificate Authority Recon', 'script': 'certificate_authority_recon.py', 'section': 'Security & Threat Intelligence'},
    {'number': '37', 'name': 'Data Leak Detection', 'script': 'data_leak.py', 'section': 'Security & Threat Intelligence'},
    {'number': '38', 'name': 'Firewall Detection', 'script': 'firewall_detection.py', 'section': 'Security & Threat Intelligence'},
    {'number': '39', 'name': 'Global Ranking', 'script': 'global_ranking.py', 'section': 'Security & Threat Intelligence'},
    {'number': '40', 'name': 'HTTP Headers', 'script': 'http_headers.py', 'section': 'Security & Threat Intelligence'},
    {'number': '41', 'name': 'HTTP Security Features', 'script': 'http_security.py', 'section': 'Security & Threat Intelligence'},
    {'number': '42', 'name': 'Malware & Phishing Check', 'script': 'malware_phishing.py', 'section': 'Security & Threat Intelligence'},
    {'number': '43', 'name': 'Pastebin Monitoring', 'script': 'pastebin_monitoring.py', 'section': 'Security & Threat Intelligence'},
    {'number': '44', 'name': 'Privacy & GDPR Compliance', 'script': 'privacy_gdpr.py', 'section': 'Security & Threat Intelligence'},
    {'number': '45', 'name': 'Security.txt Check', 'script': 'security_txt.py', 'section': 'Security & Threat Intelligence'},
    {'number': '46', 'name': 'Shodan Reconnaissance', 'script': 'shodan.py', 'section': 'Security & Threat Intelligence'},
    {'number': '47', 'name': 'SSL Labs Report', 'script': 'ssl_labs_report.py', 'section': 'Security & Threat Intelligence'},
    {'number': '48', 'name': 'SSL Pinning Check', 'script': 'ssl_pinning_check.py', 'section': 'Security & Threat Intelligence'},
    {'number': '49', 'name': 'Subdomain Enumeration', 'script': 'subdomain_enum.py', 'section': 'Security & Threat Intelligence'},
    {'number': '50', 'name': 'Subdomain Takeover', 'script': 'subdomain_takeover.py', 'section': 'Security & Threat Intelligence'},
    {'number': '51', 'name': 'VirusTotal Scan', 'script': 'virustotal_scan.py', 'section': 'Security & Threat Intelligence'},

    # Run All Scripts (53-55)
    {'number': '53', 'name': 'Run All Infrastructure Tools', 'script': '', 'section': 'Run All Scripts'},
    {'number': '54', 'name': 'Run All Web Intelligence Tools', 'script': '', 'section': 'Run All Scripts'},
    {'number': '55', 'name': 'Run All Security Tools', 'script': '', 'section': 'Run All Scripts'},

    # Special Mode
    {'number': '00', 'name': 'BEAST MODE', 'script': '', 'section': 'Special Mode'},
]


tools_mapping = {tool['number']: tool for tool in tools}


number_of_modules = len([tool for tool in tools if tool['script'] and tool['section'] not in ['Run All Scripts', 'Special Mode']])


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
import random
import time

console = Console()

from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
import random
import time

console = Console()

from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
import random
import time

console = Console()

from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
import random
import time

console = Console()

def logo():
    ascii_art = f"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝                                       
    """
    
    lines = ascii_art.strip("\n").split("\n")
    
    
    colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
    
    
    colored_lines = []
    for line in lines:
        color = random.choice(colors)
        colored_lines.append(f"[bold {color}]{line}[/bold {color}]")
        time.sleep(0.05)
    
    
    colored_ascii_art = "\n".join(colored_lines)
    
    
    description = f"""
[bold cyan]The Ultimate Information Gathering Tool[/bold cyan]

Version: [bold green]{VERSION}[/bold green]    Modules: [bold yellow]{number_of_modules}[/bold yellow]    Coded by: [bold magenta]{AUTHOR}[/bold magenta]
    """.strip()
    
    
    combined_text = f"{colored_ascii_art}\n{description}"
    panel_color = random.choice(colors)
    console.print(Panel(combined_text, border_style=panel_color, padding=(1, 4)), justify="center")




from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
import random
import time

console = Console()



def display_table():
    table = Table(box=SIMPLE_HEAVY)
    sections = ['Network & Infrastructure', 'Web Application Analysis', 'Security & Threat Intelligence']

    
    table.add_column("Network & Infrastructure", justify="left", style="cyan", no_wrap=True)
    table.add_column("Web Application Analysis", justify="left", style="green", no_wrap=True)
    table.add_column("Security & Threat Intelligence", justify="left", style="magenta", no_wrap=True)

    
    tools_by_section = defaultdict(list)
    for tool in tools:
        if tool['section'] in sections:
            tools_by_section[tool['section']].append(f"[bold]{tool['number']}[/bold]. {tool['name']}")

    max_tools = max(len(tools_by_section[section]) for section in sections)

    for idx in range(max_tools):
        row = []
        for section in sections:
            if idx < len(tools_by_section[section]):
                row.append(tools_by_section[section][idx])
            else:
                row.append("")
        table.add_row(*row)

    table.add_row("", "", "")
    table.add_row("", "", "")


    table.add_row("[bold]53[/bold]. Run All Infrastructure Tools", "[bold]54[/bold]. Run All Web Intelligence Tools", "[bold]55[/bold]. Run All Security Tools")


    table.add_row("", "", "")
    table.add_row("", "[bold red]" + "-" * 15 + " 00. BEAST MODE " + "-" * 15 + "[/bold red]", "")

    console.print(table)

def check_api_modules():
    api_status = {
        'VirusTotal': check_api_configured('VIRUSTOTAL_API_KEY'),
        'Shodan': check_api_configured('SHODAN_API_KEY'),
        'SSL Labs': check_api_configured('SSL_LABS_API_KEY'),
        'Google PageSpeed': check_api_configured('GOOGLE_PAGESPEED_API_KEY')
    }
    return api_status

# Function for BEAST MODE execution
def beast_mode():
    clear_screen()
    console.print("[bold red][*] Running BEAST MODE - Executing All Modules Except Excluded Ones[/bold red]")
    api_status = check_api_modules()

    excluded_scripts = ['subdomain_takeover.py', 'data_leak.py']

    selected_modules = [tool['number'] for tool in tools if tool['script'] and tool['script'] not in excluded_scripts and tool['number'] != '00']
    run_modules(selected_modules, api_status)


def execute_script(script_name, target):
    script_path = os.path.join("modules", script_name)
    if os.path.isfile(script_path):
        try:
            with console.status(f"[bold green]Running {script_name}...[/bold green]", spinner="dots") as status:
                process = subprocess.Popen(
                    f"{sys.executable} {script_path} {target}",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    shell=True,
                    text=True
                )

                # Real-time reading of stdout
                for line in process.stdout:
                    console.print(line.rstrip())
                    time.sleep(0.01)  # Simulate processing time

                return_code = process.wait()

                if return_code != 0:
                    console.print(f"[!] Error running {script_name}", style="bold red")

        except Exception as e:
            console.print(f"[!] An unexpected error occurred while running {script_name}: {e}", style="bold red")
    else:
        console.print(f"Script {script_name} not found in 'modules' directory.", style="bold red")


def run_modules(selected_modules, api_status):
    domain = Prompt.ask("[bold yellow]Enter the target domain or URL[/bold yellow]")
    report_data = {}

    for mod_number in selected_modules:
        tool = tools_mapping.get(mod_number)
        if tool and tool['script']:
            module_name = tool['name']
            script_name = tool['script']
            console.print(f"\n[bold cyan][+][/bold cyan] Running [bold]{module_name}[/bold]...\n")
            execute_script(script_name, domain)
        else:
            console.print(f"[!] Invalid module number: {mod_number}", style="bold red")


    generate_report(report_data, domain, [tools_mapping[mod]['name'] for mod in selected_modules])

    Prompt.ask("\n[bold yellow]Press Enter to continue...[/bold yellow]")
    main()

# Main function to handle user inputs
def main():
    clear_screen()
    logo()
    display_table()

    try:
        while True:
            choice = Prompt.ask("[bold red]root@argus:~#[/bold red]").strip()

            if choice == '00':
                beast_mode()
            elif choice == '53':  # Run all infrastructure tools
                selected_modules = [tool['number'] for tool in tools if tool['section'] == 'Network & Infrastructure']
                run_modules(selected_modules, check_api_modules())
            elif choice == '54':  # Run all web intelligence tools
                selected_modules = [tool['number'] for tool in tools if tool['section'] == 'Web Application Analysis']
                run_modules(selected_modules, check_api_modules())
            elif choice == '55':  # Run all security tools
                selected_modules = [tool['number'] for tool in tools if tool['section'] == 'Security & Threat Intelligence']
                run_modules(selected_modules, check_api_modules())
            else:
                selected_modules = [mod.strip() for mod in choice.replace(',', ' ').split()]
                if all(mod in tools_mapping for mod in selected_modules):
                    run_modules(selected_modules, check_api_modules())
                else:
                    console.print("[bold red]Invalid Input! Please choose valid options.[/bold red]")
                    display_table()

    except KeyboardInterrupt:
        console.print('\n[bold red]Script interrupted by user.[/bold red]')
        sys.exit()

if __name__ == "__main__":
    main()
