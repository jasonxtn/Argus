import sys
import os
import requests
from rich.console import Console
from rich.table import Table

# Add parent directory to sys.path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

console = Console()

def banner():
    console.print("""
[green]
=============================================
    Argus - Exposed Environment Files Checker
=============================================
[/green]
""")

def check_exposed_env_files(target):
    banner()
    target = clean_domain_input(target)
    console.print(f"[cyan][*] Checking for publicly exposed environment files on {target}...[/cyan]")

    common_files = [
        '.env',
        'env',
        'environment',
        '.env.php',
        'config.php',
        'config.yaml',
        'config.yml',
        'config.json',
        'config.ini',
        'localsettings.php',
        'settings.php',
        'db.php',
        'database.php',
        'wp-config.php',
        'appsettings.json',
        'web.config',
        '.git/config',
        '.svn/entries',
        '.hg/.hgignore',
        '.gitignore',
        'composer.lock',
        'package-lock.json',
        'yarn.lock',
        'Dockerfile',
        'docker-compose.yml',
        'Makefile',
        'requirements.txt',
        'Gemfile',
        'Pipfile',
        'Pipfile.lock',
        'setup.py',
        'phpinfo.php',
        'php.ini',
        'backup.sql',
        'dump.sql',
        'database.sql',
    ]

    found_files = []

    headers = {'User-Agent': USER_AGENT}

    for filename in common_files:
        url = f"{target}/{filename}"
        try:
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            if response.status_code == 200:
                # Check if the content is not empty and contains sensitive information
                content = response.text.strip()
                if content:
                    found_files.append({'filename': filename, 'url': url, 'status_code': response.status_code})
                    console.print(f"[green][+] Found {filename} at {url}[/green]")
            elif response.status_code in [301, 302]:
                console.print(f"[yellow][!] {filename} redirected ({response.status_code})[/yellow]")
            else:
                console.print(f"[red][-] {filename} not found ({response.status_code})[/red]")
        except requests.exceptions.RequestException as e:
            console.print(f"[red][!] Error checking {filename}: {e}[/red]")

    if found_files:
        display_results(found_files)
    else:
        console.print("[green][+] No publicly exposed environment files found.[/green]")

def display_results(found_files):
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Filename", style="white", justify="left")
    table.add_column("URL", style="white", justify="left")
    table.add_column("Status Code", style="white", justify="center")

    for file_info in found_files:
        table.add_row(file_info['filename'], file_info['url'], str(file_info['status_code']))

    console.print("\n[bold red]Warning: The following files are publicly accessible and may contain sensitive information.[/bold red]")
    console.print(table)
    console.print(f"\n[cyan][*] Exposed environment files check completed.[/cyan]")

def main(target):
    check_exposed_env_files(target)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target  # Default to HTTP if no scheme is provided
        try:
            main(target)
            sys.exit(0)  # Explicitly exit with code 0
        except KeyboardInterrupt:
            console.print("\n[red][!] Script interrupted by user.[/red]")
            sys.exit(0)  # Exit with code 0 to prevent errors in argus.py
        except Exception as e:
            console.print(f"[red][!] An unexpected error occurred: {e}[/red]")
            sys.exit(1)  # Exit with code 1 to indicate an error
    else:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
