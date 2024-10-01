import sys
import requests
from urllib.parse import urlparse
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
            Argus - Advanced Cookie Analyzer
    =============================================
    """)

def clean_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def get_cookies(url):
    try:
        session = requests.Session()
        response = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        cookies = session.cookies
        return cookies
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving cookies from {url}: {e}")
        return None

def analyze_cookies(cookies, url):
    issues = []
    for cookie in cookies:
        # Check for Secure flag
        if not cookie.secure and urlparse(url).scheme == 'https':
            issues.append(f"Cookie '{cookie.name}' is missing the Secure flag over HTTPS.")
        # Check for HttpOnly flag
        if not cookie.has_nonstandard_attr('HttpOnly'):
            issues.append(f"Cookie '{cookie.name}' is missing the HttpOnly flag.")
        # Check for SameSite attribute
        if not cookie.get_nonstandard_attr('SameSite'):
            issues.append(f"Cookie '{cookie.name}' is missing the SameSite attribute.")
    return issues

def display_cookies(cookies, url):
    table = Table(title=f"Cookies for {url}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Domain", style="yellow")
    table.add_column("Path", style="blue")
    table.add_column("Secure", style="red")
    table.add_column("HttpOnly", style="red")
    table.add_column("SameSite", style="red")
    for cookie in cookies:
        secure = 'Yes' if cookie.secure else 'No'
        httponly = 'Yes' if cookie.has_nonstandard_attr('HttpOnly') else 'No'
        samesite = cookie.get_nonstandard_attr('SameSite') or 'None'
        table.add_row(cookie.name, cookie.value, cookie.domain, cookie.path, secure, httponly, samesite)
    console.print(table)

    issues = analyze_cookies(cookies, url)
    if issues:
        console.print(Fore.YELLOW + "[!] Security Issues Detected:")
        for issue in issues:
            console.print(Fore.YELLOW + f"    - {issue}")
    else:
        console.print(Fore.GREEN + "[+] No security issues detected with cookies.")

def process_url(url):
    url = clean_url(url)
    console.print(Fore.WHITE + f"[*] Fetching cookies for: {url}")
    cookies = get_cookies(url)
    if cookies:
        display_cookies(cookies, url)
    else:
        console.print(Fore.RED + f"[!] No cookies found for {url}.")
    console.print(Fore.WHITE + f"[*] Cookie analysis completed for {url}.\n")

def main():
    banner()

    parser = argparse.ArgumentParser(description='Argus - Advanced Cookie Analyzer')
    parser.add_argument('targets', nargs='+', help='Target URLs or domains')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()

    targets = args.targets

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_url, target) for target in targets]
        for future in concurrent.futures.as_completed(futures):
            pass  # Output is handled in process_url

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
