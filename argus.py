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
from rich.box import SIMPLE_HEAVY
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from colorama import Fore, init

from utils.report_generator import generate_report
from utils.util import check_api_configured, clean_domain_input

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from config import settings

init(autoreset=True)
console = Console()

if sys.version_info < (3, 0):
    print("This script requires Python 3.")
    sys.exit(1)

VERSION = "1.1"
AUTHOR = "Jason13"

# Define tools with updated module numbers
tools = [
    # Network & Infrastructure (1-19)
    {'number': '1', 'name': 'Associated Hosts', 'script': 'associated_hosts.py', 'section': 'Network & Infrastructure'},
    {'number': '2', 'name': 'DNS Over HTTPS', 'script': 'dns_over_https.py', 'section': 'Network & Infrastructure'},
    {'number': '3', 'name': 'DNS Records', 'script': 'dns_records.py', 'section': 'Network & Infrastructure'},
    {'number': '4', 'name': 'DNSSEC Check', 'script': 'dnssec.py', 'section': 'Network & Infrastructure'},
    {'number': '5', 'name': 'Domain Info', 'script': 'domain_info.py', 'section': 'Network & Infrastructure'},
    {'number': '6', 'name': 'Domain Reputation Check', 'script': 'domain_reputation_check.py', 'section': 'Network & Infrastructure'},
    {'number': '7', 'name': 'HTTP/2 and HTTP/3 Support Checker', 'script': 'http2_http3_checker.py', 'section': 'Network & Infrastructure'},
    {'number': '8', 'name': 'IP Info', 'script': 'ip_info.py', 'section': 'Network & Infrastructure'},
    {'number': '9', 'name': 'Open Ports Scan', 'script': 'open_ports.py', 'section': 'Network & Infrastructure'},
    {'number': '10', 'name': 'Server Info', 'script': 'server_info.py', 'section': 'Network & Infrastructure'},
    {'number': '11', 'name': 'Server Location', 'script': 'server_location.py', 'section': 'Network & Infrastructure'},
    {'number': '12', 'name': 'SSL Chain Analysis', 'script': 'ssl_chain.py', 'section': 'Network & Infrastructure'},
    {'number': '13', 'name': 'SSL Expiry Alert', 'script': 'ssl_expiry.py', 'section': 'Network & Infrastructure'},
    {'number': '14', 'name': 'TLS Cipher Suites', 'script': 'tls_cipher_suites.py', 'section': 'Network & Infrastructure'},
    {'number': '15', 'name': 'TLS Handshake Simulation', 'script': 'tls_handshake.py', 'section': 'Network & Infrastructure'},
    {'number': '16', 'name': 'Traceroute', 'script': 'traceroute.py', 'section': 'Network & Infrastructure'},
    {'number': '17', 'name': 'TXT Records', 'script': 'txt_records.py', 'section': 'Network & Infrastructure'},
    {'number': '18', 'name': 'WHOIS Lookup', 'script': 'whois_lookup.py', 'section': 'Network & Infrastructure'},
    {'number': '19', 'name': 'Zone Transfer', 'script': 'zonetransfer.py', 'section': 'Network & Infrastructure'},

    # Web Application Analysis (20-36)
    {'number': '20', 'name': 'Archive History', 'script': 'archive_history.py', 'section': 'Web Application Analysis'},
    {'number': '21', 'name': 'Broken Links Detection', 'script': 'broken_links.py', 'section': 'Web Application Analysis'},
    {'number': '22', 'name': 'Carbon Footprint', 'script': 'carbon_footprint.py', 'section': 'Web Application Analysis'},
    {'number': '23', 'name': 'CMS Detection', 'script': 'cms_detection.py', 'section': 'Web Application Analysis'},
    {'number': '24', 'name': 'Cookies Analyzer', 'script': 'cookies.py', 'section': 'Web Application Analysis'},
    {'number': '25', 'name': 'Content Discovery', 'script': 'content_discovery.py', 'section': 'Web Application Analysis'},
    {'number': '26', 'name': 'Crawler', 'script': 'crawler.py', 'section': 'Web Application Analysis'},
    {'number': '27', 'name': 'Robots.txt Analyzer', 'script': 'crawl_rules.py', 'section': 'Web Application Analysis'},
    {'number': '28', 'name': 'Directory Finder', 'script': 'directory_finder.py', 'section': 'Web Application Analysis'},
    {'number': '29', 'name': 'Email Harvesting', 'script': 'email_harvester.py', 'section': 'Web Application Analysis'},
    {'number': '30', 'name': 'Performance Monitoring', 'script': 'performance_monitoring.py', 'section': 'Web Application Analysis'},
    {'number': '31', 'name': 'Quality Metrics', 'script': 'quality_metrics.py', 'section': 'Web Application Analysis'},
    {'number': '32', 'name': 'Redirect Chain', 'script': 'redirect_chain.py', 'section': 'Web Application Analysis'},
    {'number': '33', 'name': 'Sitemap Parsing', 'script': 'sitemap.py', 'section': 'Web Application Analysis'},
    {'number': '34', 'name': 'Social Media Presence Scan', 'script': 'social_media.py', 'section': 'Web Application Analysis'},
    {'number': '35', 'name': 'Technology Stack Detection', 'script': 'technology_stack.py', 'section': 'Web Application Analysis'},
    {'number': '36', 'name': 'Third-Party Integrations', 'script': 'third_party_integrations.py', 'section': 'Web Application Analysis'},

    # Security & Threat Intelligence (37-54)
    {'number': '37', 'name': 'Censys Reconnaissance', 'script': 'censys.py', 'section': 'Security & Threat Intelligence'},
    {'number': '38', 'name': 'Certificate Authority Recon', 'script': 'certificate_authority_recon.py', 'section': 'Security & Threat Intelligence'},
    {'number': '39', 'name': 'Data Leak Detection', 'script': 'data_leak.py', 'section': 'Security & Threat Intelligence'},
    {'number': '40', 'name': 'Exposed Environment Files Checker', 'script': 'exposed_env_files.py', 'section': 'Security & Threat Intelligence'},
    {'number': '41', 'name': 'Firewall Detection', 'script': 'firewall_detection.py', 'section': 'Security & Threat Intelligence'},
    {'number': '42', 'name': 'Global Ranking', 'script': 'global_ranking.py', 'section': 'Security & Threat Intelligence'},
    {'number': '43', 'name': 'HTTP Headers', 'script': 'http_headers.py', 'section': 'Security & Threat Intelligence'},
    {'number': '44', 'name': 'HTTP Security Features', 'script': 'http_security.py', 'section': 'Security & Threat Intelligence'},
    {'number': '45', 'name': 'Malware & Phishing Check', 'script': 'malware_phishing.py', 'section': 'Security & Threat Intelligence'},
    {'number': '46', 'name': 'Pastebin Monitoring', 'script': 'pastebin_monitoring.py', 'section': 'Security & Threat Intelligence'},
    {'number': '47', 'name': 'Privacy & GDPR Compliance', 'script': 'privacy_gdpr.py', 'section': 'Security & Threat Intelligence'},
    {'number': '48', 'name': 'Security.txt Check', 'script': 'security_txt.py', 'section': 'Security & Threat Intelligence'},
    {'number': '49', 'name': 'Shodan Reconnaissance', 'script': 'shodan.py', 'section': 'Security & Threat Intelligence'},
    {'number': '50', 'name': 'SSL Labs Report', 'script': 'ssl_labs_report.py', 'section': 'Security & Threat Intelligence'},
    {'number': '51', 'name': 'SSL Pinning Check', 'script': 'ssl_pinning_check.py', 'section': 'Security & Threat Intelligence'},
    {'number': '52', 'name': 'Subdomain Enumeration', 'script': 'subdomain_enum.py', 'section': 'Security & Threat Intelligence'},
    {'number': '53', 'name': 'Subdomain Takeover', 'script': 'subdomain_takeover.py', 'section': 'Security & Threat Intelligence'},
    {'number': '54', 'name': 'VirusTotal Scan', 'script': 'virustotal_scan.py', 'section': 'Security & Threat Intelligence'},

    {'number': '100', 'name': 'Run All Infrastructure Tools', 'script': '', 'section': 'Run All Scripts'},
    {'number': '200', 'name': 'Run All Web Intelligence Tools', 'script': '', 'section': 'Run All Scripts'},
    {'number': '300', 'name': 'Run All Security Tools', 'script': '', 'section': 'Run All Scripts'},

    # Special Mode
    {'number': '00', 'name': 'BEAST MODE', 'script': '', 'section': 'Special Mode'},
]

# Create a mapping for quick tool lookup
tools_mapping = {tool['number']: tool for tool in tools}

# Count the number of modules
number_of_modules = len([tool for tool in tools if tool['script'] and tool['section'] not in ['Run All Scripts', 'Special Mode']])

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

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
    table.add_row("[bold]100[/bold]. Run All Infrastructure Tools", "[bold]200[/bold]. Run All Web Intelligence Tools", "[bold]300[/bold]. Run All Security Tools")
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
    console.print("[bold red][*] Running BEAST MODE - Executing All Modules [/bold red]")
    api_status = check_api_modules()
    excluded_scripts = ['subdomain_takeover.py', 'data_leak.py']
    selected_modules = [tool['number'] for tool in tools if tool['script'] and tool['script'] not in excluded_scripts and tool['number'] != '00']
    run_modules(selected_modules, api_status, mode_name='BEAST_MODE')

def execute_script(script_name, target):
    script_path = os.path.join("modules", script_name)
    if os.path.isfile(script_path):
        try:
            with console.status(f"[bold green]Running {script_name}...[/bold green]", spinner="dots"):
                process = subprocess.Popen(
                    [sys.executable, script_path, target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                for line in iter(process.stdout.readline, ''):
                    if line:
                        console.print(line.strip())
                    else:
                        break
                process.stdout.close()
                return_code = process.wait()
                if return_code != 0:
                    console.print(f"[!] Error running {script_name}", style="bold red")
        except Exception as e:
            console.print(f"[!] An unexpected error occurred while running {script_name}: {e}", style="bold red")
    else:
        console.print(f"Script {script_name} not found in 'modules' directory.", style="bold red")

def run_modules(selected_modules, api_status, mode_name=None):
    domain = Prompt.ask("[bold yellow]Enter the target domain or URL[/bold yellow]")
    domain = clean_domain_input(domain)
    report_data = {}

    for mod_number in selected_modules:
        tool = tools_mapping.get(mod_number)
        if tool and tool['script']:
            module_name = tool['name']
            script_name = tool['script']
            output = execute_script(script_name, domain)
            if output:
                report_data[module_name] = output
                console.print(output)
        else:
            console.print(f"[!] Invalid module number: {mod_number}", style="bold red")

    if mode_name:
        module_names = [mode_name]
    elif len(selected_modules) == 1:
        module_names = [tools_mapping[selected_modules[0]]['name']]
    else:
        module_names = ['multiple_modules']

    generate_report(report_data, domain, module_names)

    Prompt.ask("\n[bold yellow]Press Enter to continue...[/bold yellow]")
    main()

def main():
    clear_screen()
    logo()
    display_table()

    try:
        while True:
            choice = Prompt.ask("[bold red]root@argus:~#[/bold red]").strip()

            if choice == '00':
                beast_mode()
            elif choice == '100':  # Run all infrastructure tools
                selected_modules = [tool['number'] for tool in tools if tool['section'] == 'Network & Infrastructure']
                run_modules(selected_modules, check_api_modules(), mode_name='All_Infrastructure_Tools')
            elif choice == '200':  # Run all web intelligence tools
                selected_modules = [tool['number'] for tool in tools if tool['section'] == 'Web Application Analysis']
                run_modules(selected_modules, check_api_modules(), mode_name='All_Web_Intelligence_Tools')
            elif choice == '300':  # Run all security tools
                selected_modules = [tool['number'] for tool in tools if tool['section'] == 'Security & Threat Intelligence']
                run_modules(selected_modules, check_api_modules(), mode_name='All_Security_Tools')
            elif choice.lower() in ['exit', 'quit']:
                console.print("[bold green]Exiting Argus. Goodbye![/bold green]")
                sys.exit(0)
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
