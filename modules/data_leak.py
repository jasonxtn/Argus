import sys
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
import threading
import queue
import time

init(autoreset=True)
console = Console()
lock = threading.Lock()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced Data Leak Checker
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    parsed_url = urlparse(domain)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return domain

def get_email_addresses(domain):
    # Generate common email patterns
    common_usernames = ['admin', 'contact', 'info', 'support', 'sales', 'webmaster', 'postmaster']
    emails = [f"{username}@{domain}" for username in common_usernames]
    return emails

def check_email_breaches(email, session):
    url = f"https://leak-lookup.com/search?query={email}"
    headers = {
        'User-Agent': 'ArgusDataLeakChecker/1.0'
    }
    try:
        response = session.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            # Simulate parsing the response as the actual implementation depends on the source
            if "No leaks found" in response.text:
                return []
            else:
                # Extract breach information from the response
                breaches = parse_breaches(response.text)
                return breaches
        else:
            with lock:
                console.print(Fore.RED + f"[!] Error checking {email}: HTTP {response.status_code}")
            return None
    except requests.RequestException as e:
        with lock:
            console.print(Fore.RED + f"[!] Error checking {email}: {e}")
        return None

def parse_breaches(html_content):
    # Placeholder function to parse breaches from HTML content
    # In a real implementation, you'd parse the HTML to extract breach data
    breaches = [
        {
            'Name': 'ExampleBreach',
            'Date': '2022-01-01',
            'DataClasses': ['Emails', 'Passwords']
        }
    ]
    return breaches

def display_breaches(email, breaches):
    if not breaches:
        with lock:
            console.print(Fore.GREEN + f"[+] No breaches found for {email}")
        return
    table = Table(title=f"Breaches for {email}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Name", style="cyan", justify="left")
    table.add_column("Breach Date", style="white")
    table.add_column("Data Classes", style="yellow")
    for breach in breaches:
        name = breach.get('Name', 'N/A')
        breach_date = breach.get('Date', 'N/A')
        data_classes = ', '.join(breach.get('DataClasses', []))
        table.add_row(name, breach_date, data_classes)
    with lock:
        console.print(table)

def worker(email_queue, session):
    while True:
        email = email_queue.get()
        if email is None:
            break
        with lock:
            console.print(Fore.YELLOW + f"[*] Checking {email}")
        breaches = check_email_breaches(email, session)
        if breaches is None:
            email_queue.task_done()
            continue  # Skip to next email if there was an error
        display_breaches(email, breaches)
        email_queue.task_done()

def main():
    banner()
    parser = argparse.ArgumentParser(description='Argus - Advanced Data Leak Checker')
    parser.add_argument('domain', help='Domain to check for data leaks')
    parser.add_argument('--email', action='append', help='Specific email addresses to check (can be used multiple times)')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()

    domain = clean_domain_input(args.domain)

    if args.email:
        emails = args.email
    else:
        emails = get_email_addresses(domain)

    console.print(Fore.WHITE + f"[*] Checking data leaks for domain: {domain}")

    email_queue = queue.Queue()
    session = requests.Session()

    # Start worker threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(email_queue, session))
        t.start()
        threads.append(t)

    # Enqueue emails
    for email in emails:
        email_queue.put(email)

    # Wait for all emails to be processed
    email_queue.join()

    # Stop workers
    for _ in range(args.threads):
        email_queue.put(None)
    for t in threads:
        t.join()

    console.print(Fore.CYAN + "[*] Data leak check completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
