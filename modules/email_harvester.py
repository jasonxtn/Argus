import sys
import os
import threading
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import HEADERS, DEFAULT_TIMEOUT

console = Console()

def banner():
    console.print("""
[green]
=============================================
       Argus - Email Harvesting Module
=============================================
[/green]
""")

class EmailHarvester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.emails_found = set()
        self.urls_queue = deque()
        self.headers = HEADERS
        self.max_pages = 100
        self.lock = threading.Lock()
        self.num_threads = 10
        self.page_count = 0

    def crawl(self):
        self.urls_queue.append(self.base_url)
        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def worker(self):
        while True:
            with self.lock:
                if not self.urls_queue or self.page_count >= self.max_pages:
                    break
                url = self.urls_queue.popleft()
                if url in self.visited_urls:
                    continue
                self.visited_urls.add(url)
                self.page_count += 1
            try:
                response = requests.get(url, headers=self.headers, timeout=DEFAULT_TIMEOUT)
                if response.status_code == 200:
                    self.extract_emails(response.text)
                    self.extract_links(response.text, url)
                    console.print(f"[cyan][*] Crawled: {url}[/cyan]")
                else:
                    console.print(f"[yellow][!] Skipped {url} (Status code: {response.status_code})[/yellow]")
            except requests.exceptions.RequestException as e:
                console.print(f"[red][!] Error crawling {url}: {e}[/red]")

    def extract_emails(self, html_content):
        emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_content))
        new_emails = emails - self.emails_found
        if new_emails:
            with self.lock:
                self.emails_found.update(new_emails)
            for email in new_emails:
                console.print(f"[green][+] Found email: {email}[/green]")
            console.print(f"[magenta]Total emails found so far: {len(self.emails_found)}[/magenta]")

    def extract_links(self, html_content, current_url):
        soup = BeautifulSoup(html_content, 'html.parser')
        new_urls = set()
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            full_url = urljoin(current_url, href)
            if self.is_valid_url(full_url):
                if full_url not in self.visited_urls:
                    new_urls.add(full_url)
        with self.lock:
            self.urls_queue.extend(new_urls - self.visited_urls)

    def is_valid_url(self, url):
        parsed_base = urlparse(self.base_url)
        parsed_url = urlparse(url)
        return parsed_url.scheme in ('http', 'https') and parsed_url.netloc == parsed_base.netloc

    def display_results(self):
        if self.emails_found:
            table = Table(show_header=True, header_style="bold white")
            table.add_column("Email Addresses Found", style="white", justify="left")
            for email in sorted(self.emails_found):
                table.add_row(email)
            console.print(table)
            console.print(f"\n[cyan][*] Email harvesting completed. Total emails found: {len(self.emails_found)}[/cyan]")
        else:
            console.print("[yellow][!] No email addresses found.[/yellow]")

def main(target):
    banner()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    harvester = EmailHarvester(target)
    console.print(f"[cyan][*] Starting email harvesting on {target}...[/cyan]")
    harvester.crawl()
    harvester.display_results()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
            sys.exit(0)
        except KeyboardInterrupt:
            console.print("\n[red][!] Script interrupted by user.[/red]")
            sys.exit(0)
        except Exception as e:
            console.print(f"[red][!] An unexpected error occurred: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
