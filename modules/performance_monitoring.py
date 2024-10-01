import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import init

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url
from config.settings import DEFAULT_TIMEOUT, GOOGLE_API_KEY  

init(autoreset=True)
console = Console()

def banner():
    console.print("""
[green]
    =============================================
           Argus - Performance Monitoring
    =============================================
[/green]
    """)

def get_performance_metrics(url):
    try:
        clean_target = clean_url(url)
        if not GOOGLE_API_KEY:
            console.print("[red][!] Google API key not configured. Please set your API key in the configuration file.[/red]")
            return None

        api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={clean_target}&strategy=mobile&key={GOOGLE_API_KEY}"
        response = requests.get(api_url, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            console.print("[red][!] Access Denied. Please check if your Google API key has the correct permissions.[/red]")
            return None
        elif response.status_code == 400:
            console.print("[red][!] Bad Request. The URL or parameters might be incorrect. Please verify the URL and try again.[/red]")
            return None
        else:
            console.print(f"[red][!] Error: Received status code {response.status_code} from the API. Please verify your API key and target URL.[/red]")
            return None

    except requests.RequestException as e:
        console.print(f"[red][!] Error retrieving performance metrics: {e}[/red]")
        return None

def display_performance_metrics(metrics):
    if metrics:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", justify="left")
        table.add_column("Value", style="green")

        performance_score = metrics.get("lighthouseResult", {}).get("categories", {}).get("performance", {}).get("score", "N/A")
        table.add_row("Performance Score", str(performance_score * 100 if isinstance(performance_score, float) else "N/A"))

        console.print(table)
    else:
        console.print("[red][!] No performance data to display.[/red]")

def main(target):
    banner()
    console.print(f"[white][*] Fetching performance metrics for: {target}[/white]")
    metrics = get_performance_metrics(target)
    if metrics:
        display_performance_metrics(metrics)
    else:
        console.print("[red][!] Could not retrieve performance metrics.[/red]")
    console.print("[white][*] Performance monitoring completed.[/white]")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
        except KeyboardInterrupt:
            console.print("\n[red][!] Process interrupted by user.[/red]")
            sys.exit(1)
    else:
        console.print("[red][!] No target provided. Please pass a URL as an argument.[/red]")
        sys.exit(1)
