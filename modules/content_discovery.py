import os
import sys
import requests
import asyncio
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import (
    clean_url,
    validate_domain,
    ensure_directory_exists,
    ensure_url_format,
    clean_domain_input,
)
from config.settings import DEFAULT_TIMEOUT, RESULTS_DIR

init(autoreset=True)
console = Console()

def banner():
    console.print(
        Fore.GREEN
        + """
    =============================================
            Argus - Content Discovery
    =============================================
    """
    )

def structure_url(target, link):
    if link.startswith("/"):
        return target + link
    elif link.startswith("//"):
        return "http:" + link
    elif link.startswith("http"):
        return link
    return None

async def get_robots_txt(base_url):
    console.print(Fore.WHITE + f"[*] Fetching robots.txt from: {base_url}/robots.txt")
    try:
        response = requests.get(f"{base_url}/robots.txt", timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            console.print(Fore.GREEN + "[+] Found robots.txt")
            return response.text
        else:
            console.print(Fore.YELLOW + "[!] robots.txt not found.")
            return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error fetching robots.txt: {e}")
        return None

async def discover_sitemap(base_url):
    sitemap_url = f"{base_url}/sitemap.xml"
    console.print(Fore.WHITE + f"[*] Checking {sitemap_url}")
    try:
        response = requests.get(sitemap_url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            console.print(Fore.GREEN + "[+] Found sitemap.xml")
            soup = BeautifulSoup(response.content, "html.parser")
            links = [loc.text for loc in soup.find_all("loc")]
            return links
        else:
            console.print(Fore.YELLOW + "[!] sitemap.xml not found.")
            return []
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error fetching sitemap.xml: {e}")
        return []

async def discover_internal_links(target, soup):
    internal_links = []
    console.print(Fore.WHITE + "[*] Discovering internal links...")
    for link in soup.find_all("a", href=True):
        url = structure_url(target, link.get("href"))
        if url:
            internal_links.append(url)
    internal_links = list(set(internal_links))
    return internal_links

async def discover_external_links(target, soup):
    external_links = []
    console.print(Fore.WHITE + "[*] Discovering external links...")
    for link in soup.find_all("a", href=True):
        url = link.get("href")
        if url and url.startswith("http") and target not in url:
            external_links.append(url)
    external_links = list(set(external_links))
    return external_links

async def discover_assets(target, soup, asset_type):
    assets = []
    tag, attr = ("link", "href") if asset_type == "css" else ("script", "src")
    console.print(Fore.WHITE + f"[*] Discovering {asset_type.upper()} files...")
    for asset in soup.find_all(tag, **{attr: True}):
        url = structure_url(target, asset.get(attr))
        if url:
            assets.append(url)
    return list(set(assets))

def display_results(robots_txt, sitemaps, internal_links, external_links, css_files, js_files):
    if css_files or js_files:
        asset_table = Table(show_header=True, header_style="bold magenta", box=None)  # Open sides for easy copying
        asset_table.add_column("Asset Type", style="WHITE", justify="left")
        asset_table.add_column("Link", style="green", overflow="fold")

        for css_file in css_files:
            asset_table.add_row("CSS File", css_file)
        for js_file in js_files:
            asset_table.add_row("JS File", js_file)

        console.print("\n" + Fore.WHITE + "[*] Asset Files Found:")
        console.print(asset_table)

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Category", style="cyan", justify="left")
    summary_table.add_column("Count", style="green")

    if robots_txt:
        summary_table.add_row("robots.txt", "Available")
    else:
        summary_table.add_row("robots.txt", "Not Found")
    summary_table.add_row("Sitemap Links", str(len(sitemaps)))
    summary_table.add_row("Internal Links", str(len(internal_links)))
    summary_table.add_row("External Links", str(len(external_links)))
    summary_table.add_row("CSS Files", str(len(css_files)))
    summary_table.add_row("JS Files", str(len(js_files)))

    console.print(summary_table)

async def content_discovery(target, output):
    banner()
    console.print(Fore.WHITE + f"[*] Starting content discovery for {target}")

    target = ensure_url_format(target)
    parsed_url = urlparse(clean_url(target))
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    try:
        response = requests.get(target, timeout=DEFAULT_TIMEOUT)
        if response.status_code != 200:
            console.print(
                Fore.RED + f"[!] Failed to access {target}, status code {response.status_code}"
            )
            return

        soup = BeautifulSoup(response.content, "html.parser")

        # Asynchronous tasks
        robots_task = asyncio.create_task(get_robots_txt(base_url))
        sitemap_task = asyncio.create_task(discover_sitemap(base_url))
        internal_links_task = asyncio.create_task(discover_internal_links(target, soup))
        external_links_task = asyncio.create_task(discover_external_links(target, soup))
        css_task = asyncio.create_task(discover_assets(target, soup, "css"))
        js_task = asyncio.create_task(discover_assets(target, soup, "js"))

        # Gather results from all tasks
        (
            robots_txt,
            sitemaps,
            internal_links,
            external_links,
            css_files,
            js_files,
        ) = await asyncio.gather(
            robots_task,
            sitemap_task,
            internal_links_task,
            external_links_task,
            css_task,
            js_task,
        )

        display_results(robots_txt, sitemaps, internal_links, external_links, css_files, js_files)

    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error during content discovery for {target}: {e}")

def main(input_target):
    banner()
    domain = clean_domain_input(input_target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain provided. Please check and try again.")
        return

    target = ensure_url_format(input_target)
    ensure_directory_exists(RESULTS_DIR)

    output_settings = {"directory": RESULTS_DIR, "format": "html"}
    asyncio.run(content_discovery(target, output_settings))

if __name__ == "__main__":
    try:
        target_domain = (
            sys.argv[1] if len(sys.argv) > 1 else input("Enter domain for content discovery: ")
        )
        main(target_domain)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Content discovery interrupted by user.")
        sys.exit(1)
