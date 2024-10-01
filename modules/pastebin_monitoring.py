import os
import sys
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import re
from urllib.parse import urljoin, urlparse
import base64
import dns.resolver
import argparse

# Add the parent directory to the system path to import utilities and settings
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.util import log_message
from config.settings import API_KEYS

init(autoreset=True)
console = Console()

# Define sensitive data patterns
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
API_KEY_REGEX = re.compile(r'api[_-]?key[:=]\s*[A-Za-z0-9]{10,}')
PASSWORD_REGEX = re.compile(r'password[:=]\s*[A-Za-z0-9@#$%^&+=]{6,}')

# Define paste sites configurations
PASTE_SITES = {
    "Pastebin": {
        "search_url": "https://pastebin.com/search",
        "paste_link_prefix": "https://pastebin.com",
        "paste_link_pattern": re.compile(r'^/[A-Za-z0-9]{8}$'),
    },
    "Ghostbin": {
        "search_url": "https://ghostbin.com/search",
        "paste_link_prefix": "https://ghostbin.com",
        "paste_link_pattern": re.compile(r'^/p/[A-Za-z0-9]{6}$'),
    },
    "Paste.ee": {
        "search_url": "https://api.paste.ee/v1/pastes/search",
        "paste_link_prefix": "https://paste.ee/p/",
        "paste_link_pattern": re.compile(r'^/p/[A-Za-z0-9]{6,}$'),
    },
    "ControlC": {
        "search_url": "https://controlc.com/search",
        "paste_link_prefix": "https://controlc.com",
        "paste_link_pattern": re.compile(r'^/[\w]{4,}$'),
    },
    "Paste.org": {
        "search_url": "https://paste.org/search",
        "paste_link_prefix": "https://paste.org",
        "paste_link_pattern": re.compile(r'^/[\w-]{6,}$'),
    }
}

MAX_PAGES = 2  # Define maximum pages to search
DEFAULT_TIMEOUT = 10  # Default timeout for HTTP requests

async def fetch_url(session, url, params=None):
    try:
        async with session.get(url, params=params, timeout=DEFAULT_TIMEOUT) as response:
            if response.status == 200:
                return await response.text()
            else:
                console.print(Fore.RED + f"[!] Failed to fetch {url} with status {response.status}.")
                return None
    except asyncio.TimeoutError:
        console.print(Fore.RED + f"[!] Timeout occurred while fetching {url}.")
    except Exception as e:
        console.print(Fore.RED + f"[!] Error fetching {url}: {e}")
    return None

async def post_url(session, url, data=None, headers=None):
    try:
        async with session.post(url, json=data, headers=headers, timeout=DEFAULT_TIMEOUT) as response:
            if response.status in [200, 201]:
                return await response.json()
            else:
                console.print(Fore.RED + f"[!] POST request to {url} failed with status {response.status}.")
                return None
    except asyncio.TimeoutError:
        console.print(Fore.RED + f"[!] Timeout occurred while posting to {url}.")
    except Exception as e:
        console.print(Fore.RED + f"[!] Error posting to {url}: {e}")
    return None

async def search_paste_site(session, site_name, query):
    site = PASTE_SITES.get(site_name)
    if not site:
        console.print(Fore.RED + f"[!] Paste site {site_name} is not configured.")
        return []

    results = []
    for page in range(1, MAX_PAGES + 1):
        if site_name == "Paste.ee":
            # Paste.ee uses POST requests for search
            search_payload = {
                'query': query,
                'page': page
            }
            headers = {
                'Content-Type': 'application/json'
            }
            console.print(Fore.YELLOW + f"[*] Searching {site_name} - Page {page}...")
            html_content = await post_url(session, site['search_url'], data=search_payload, headers=headers)
            if html_content:
                parsed_results = parse_paste_site_results(site_name, html_content, site)
                if not parsed_results:
                    console.print(Fore.YELLOW + f"[!] No more results found on {site_name} at page {page}.")
                    break
                results.extend(parsed_results)
        else:
            # Other sites use GET requests
            params = {'q': query, 'page': page}
            console.print(Fore.YELLOW + f"[*] Searching {site_name} - Page {page}...")
            html_content = await fetch_url(session, site['search_url'], params=params)
            if html_content:
                parsed_results = parse_paste_site_results(site_name, html_content, site)
                if not parsed_results:
                    console.print(Fore.YELLOW + f"[!] No more results found on {site_name} at page {page}.")
                    break
                results.extend(parsed_results)
        await asyncio.sleep(1)  # Small delay to prevent overwhelming the site
    return results

def parse_paste_site_results(site_name, html_content, site):
    pastes = []
    if site_name == "Paste.ee":
        # Paste.ee returns JSON
        if not html_content.get("data"):
            return pastes
        for paste in html_content['data']:
            paste_title = paste.get('title') or "No Title"
            paste_link = site['paste_link_prefix'] + paste['id']
            pastes.append({'title': paste_title, 'link': paste_link, 'site': site_name})
    else:
        soup = BeautifulSoup(html_content, 'html.parser')
        for paste in soup.find_all('a', href=site['paste_link_pattern']):
            paste_title = paste.text.strip() or "No Title"
            paste_link = urljoin(site['paste_link_prefix'], paste['href'])
            pastes.append({'title': paste_title, 'link': paste_link, 'site': site_name})
    return pastes

def display_pastebin_results(results):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Site", style="cyan", justify="left")
    table.add_column("Title", style="cyan", justify="left")
    table.add_column("Link", style="green", justify="left")

    for result in results:
        table.add_row(result['site'], result['title'], result['link'])

    console.print(table)

async def retrieve_paste_content(session, paste):
    try:
        console.print(Fore.YELLOW + f"[*] Retrieving content from {paste['link']}...")
        content = await fetch_url(session, paste['link'])
        if content:
            return content
    except Exception as e:
        console.print(Fore.RED + f"[!] Error retrieving paste content from {paste['link']}: {e}")
    return ""

def analyze_content(paste, content):
    findings = {}

    emails = EMAIL_REGEX.findall(content)
    api_keys = API_KEY_REGEX.findall(content)
    passwords = PASSWORD_REGEX.findall(content)

    if emails:
        findings['Emails'] = emails
    if api_keys:
        findings['API Keys'] = api_keys
    if passwords:
        findings['Passwords'] = passwords

    if findings:
        display_findings(paste, findings)
        log_findings(paste, findings)

def display_findings(paste, findings):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Site", style="cyan", justify="left")
    table.add_column("Title", style="cyan", justify="left")
    table.add_column("Link", style="green", justify="left")
    table.add_column("Findings", style="red", justify="left")

    findings_summary = "; ".join([f"{key}: {len(value)} found" for key, value in findings.items()])
    table.add_row(paste['site'], paste['title'], paste['link'], findings_summary)

    console.print(table)

def log_findings(paste, findings):
    log_entry = f"Site: {paste['site']}, Title: {paste['title']}, Link: {paste['link']}\n"
    for key, values in findings.items():
        log_entry += f"  {key}:\n"
        for value in values:
            log_entry += f"    - {value}\n"
    log_message("paste_monitoring.log", log_entry)

async def check_blacklist_services(domain):
    console.print(Fore.YELLOW + "[*] Checking blacklist services...")
    blacklist_domains = [
        "zen.spamhaus.org",
        "b.barracudacentral.org"
        # Add more blacklist services if needed
    ]
    listed = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for blacklist in blacklist_domains:
            query = f"{'.'.join(reversed(domain.split('.')))}.{blacklist}"
            try:
                answers = resolver.resolve(query, 'A')
                for rdata in answers:
                    if rdata.address.startswith("127."):
                        console.print(Fore.RED + f"[!] Domain {domain} is listed in {blacklist}.")
                        log_message("paste_monitoring.log", f"Domain {domain} is listed in {blacklist}.")
                        listed = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as e:
                console.print(Fore.RED + f"[!] DNS query error for {blacklist}: {e}")
                log_message("paste_monitoring.log", f"DNS query error for {blacklist}: {e}")
        if not listed:
            console.print(Fore.GREEN + "[+] Domain not found in public blacklist services.")
            log_message("paste_monitoring.log", f"Domain not found in public blacklist services.")
    except Exception as e:
        console.print(Fore.RED + f"[!] Error during blacklist services check: {e}")
        log_message("paste_monitoring.log", f"Error during blacklist services check: {e}")

async def check_virustotal(session, domain):
    console.print(Fore.YELLOW + "[*] Checking VirusTotal...")
    api_key = API_KEYS.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        console.print(Fore.RED + "[!] VirusTotal API key not configured.")
        log_message("paste_monitoring.log", "VirusTotal API key not configured.")
        return

    try:
        # Step 1: Submit the domain to VirusTotal for analysis
        scan_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            'x-apikey': api_key
        }
        async with session.get(scan_url, headers=headers, timeout=DEFAULT_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    console.print(Fore.RED + f"[!] VirusTotal detected {malicious} malicious sources for domain {domain}.")
                    log_message("paste_monitoring.log", f"VirusTotal detected {malicious} malicious sources for domain {domain}.")
                else:
                    console.print(Fore.GREEN + f"[+] VirusTotal found no malicious sources for domain {domain}.")
                    log_message("paste_monitoring.log", f"VirusTotal found no malicious sources for domain {domain}.")
            else:
                console.print(Fore.RED + f"[!] VirusTotal check failed with status code {response.status}.")
                log_message("paste_monitoring.log", f"VirusTotal check failed with status code {response.status}.")
    except asyncio.TimeoutError:
        console.print(Fore.RED + "[!] Timeout occurred during VirusTotal check.")
        log_message("paste_monitoring.log", "Timeout occurred during VirusTotal check.")
    except Exception as e:
        console.print(Fore.RED + f"[!] Error during VirusTotal check: {e}")
        log_message("paste_monitoring.log", f"Error during VirusTotal check: {e}")

async def monitor_paste_sites(query):
    all_results = []

    async with aiohttp.ClientSession() as session:
        # Search all paste sites concurrently
        tasks = []
        for site in PASTE_SITES.keys():
            tasks.append(search_paste_site(session, site, query))

        paste_results = await asyncio.gather(*tasks)

        for site_results in paste_results:
            if site_results:
                all_results.extend(site_results)

        if all_results:
            display_pastebin_results(all_results)
            # Analyze each paste content concurrently
            analysis_tasks = []
            for paste in all_results:
                analysis_tasks.append(analyze_paste_content(session, paste))
            await asyncio.gather(*analysis_tasks)
        else:
            console.print(Fore.YELLOW + "[!] No pastes found for the given query.")

async def analyze_paste_content(session, paste):
    content = await retrieve_paste_content(session, paste)
    if content:
        analyze_content(paste, content)
        # Extract domain from paste link
        parsed_url = urlparse(paste['link'])
        domain = parsed_url.netloc
        if domain:
            await check_blacklist_services(domain)
            await check_virustotal(session, domain)

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced Paste Monitoring
    =============================================
    """)

def main(query):
    banner()
    console.print(Fore.WHITE + f"[*] Monitoring paste sites for query: {query}")
    asyncio.run(monitor_paste_sites(query))
    console.print(Fore.CYAN + "[*] Paste monitoring completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus - Advanced Paste Monitoring Tool")
    parser.add_argument('query', type=str, help='Search query to monitor on paste sites')
    args = parser.parse_args()

    try:
        query = args.query.strip()
        if not query:
            console.print(Fore.RED + "[!] Query cannot be empty.")
            sys.exit(1)
        main(query)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
