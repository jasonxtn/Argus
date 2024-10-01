import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

# Initialize the console for rich output
console = Console()

def banner():
    console.print("""
=============================================
        Argus - Broken Links Detection
=============================================
""")

def sanitize_input(target):
    return target.strip()

def ensure_url_format(target):
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return target

def clean_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return clean

def check_links_with_w3c(target):
    w3c_link_checker_url = "https://validator.w3.org/checklink"

    params = {
        'uri': target,
        'hide_type': 'all',  # Show all link types
        'recursive': 'on',   # Check links recursively
        'depth': '1',        # Depth level
        'check': 'Check'     # Submit button name
    }

    try:
        response = requests.get(w3c_link_checker_url, params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        console.print(f"[!] Error accessing W3C Link Checker: {e}")
        return []

    soup = BeautifulSoup(response.content, 'html.parser')
    broken_links = []

    # Find all 'tr' elements with class 'status-404' or other error statuses
    error_rows = soup.find_all('tr', class_='status-404')
    error_rows += soup.find_all('tr', class_='status-403')
    error_rows += soup.find_all('tr', class_='status-500')
    error_rows += soup.find_all('tr', class_='status-0')

    for row in error_rows:
        link_cell = row.find('td', class_='uri')
        if link_cell:
            link = link_cell.get_text(strip=True)
            broken_links.append(link)

    return broken_links

def display_broken_links(broken_links, domain):
    if not broken_links:
        console.print(f"[+] No broken links found for {domain}.")
        return

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Broken Link", style="red", min_width=60)

    for link in broken_links:
        table.add_row(link)

    console.print(table)
    console.print(f"\n[*] Broken link detection completed for {domain}.")

def broken_links_detection(target):
    banner()
    target = sanitize_input(target)
    target = ensure_url_format(target)
    target = clean_url(target)

    console.print(f"[*] Checking links on: {target}\n")

    broken_links = check_links_with_w3c(target)

    display_broken_links(broken_links, target)

def main(target):
    broken_links_detection(target)

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
        console.print("[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
