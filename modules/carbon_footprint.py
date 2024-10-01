import sys
import requests
from rich.console import Console
from rich.table import Table

console = Console()

def banner():
    console.print("""
==============================================
 Argus - Website Carbon Footprint Calculator
==============================================
""")

def sanitize_input(target):
    return target.strip()

def ensure_url_format(target):
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return target

def get_carbon_footprint(url):
    api_url = f"https://api.websitecarbon.com/site?url={url}"
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        console.print(f"[!] Error accessing API: {e}")
        return None

def display_results(data, url):
    if data is None:
        console.print("[!] Unable to retrieve carbon footprint data.")
        return

    green = data.get('green', False)
    cleaner_than = data.get('cleanerThan', 0) * 100  # Convert to percentage
    statistics = data.get('statistics', {})

    console.print(f"Results for {url}:\n")
    console.print(f"Is the website hosted on green hosting? {'Yes' if green else 'No'}")
    console.print(f"Website is cleaner than {cleaner_than:.2f}% of websites tested.\n")

    # Safely extract 'co2' data
    co2_data = statistics.get('co2', {})
    if isinstance(co2_data, dict):
        grid_co2 = co2_data.get('grid', {})
        co2_per_view = grid_co2.get('grams', 0) if isinstance(grid_co2, dict) else grid_co2
        renewable_co2 = co2_data.get('renewable', {})
        co2_per_view_renewable = renewable_co2.get('grams', 0) if isinstance(renewable_co2, dict) else renewable_co2
    else:
        co2_per_view = co2_data
        co2_per_view_renewable = 0

    # Safely extract 'energy' data
    energy_data = statistics.get('energy', {})
    if isinstance(energy_data, dict):
        grid_energy = energy_data.get('grid', 0)
        energy_per_view = grid_energy
    else:
        energy_per_view = energy_data

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Carbon emitted per page view (grid energy)", f"{co2_per_view:.4f} grams")
    table.add_row("Carbon emitted per page view (renewable energy)", f"{co2_per_view_renewable:.4f} grams")
    table.add_row("Energy consumed per page view", f"{energy_per_view:.6f} kWh")

    console.print(table)

def main(target_url):
    banner()
    target_url = sanitize_input(target_url)
    target_url = ensure_url_format(target_url)

    console.print(f"[*] Analyzing website: {target_url}\n")

    data = get_carbon_footprint(target_url)
    display_results(data, target_url)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
            sys.exit(0)
        except KeyboardInterrupt:
            console.print("\n[!] Script interrupted by user.")
            sys.exit(0)
        except Exception as e:
            console.print(f"[!] An unexpected error occurred: {e}")
            sys.exit(1)
    else:
        console.print("[!] No target provided. Please pass a website URL.")
        sys.exit(1)
