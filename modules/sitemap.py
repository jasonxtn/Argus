import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
from urllib.parse import urljoin, urlparse
import aiohttp
import asyncio

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10  # seconds


def banner():
    console.print(Fore.GREEN + """
=============================================
           Argus - Sitemap Analysis
=============================================
""")


def convert_to_url(target):
    parsed = urlparse(target)
    if not parsed.scheme:
        return f"http://{target}"
    return target


async def get_sitemap_urls(base_url):
    potential_sitemaps = [
        'sitemap.xml',
        'sitemap_index.xml',
        'sitemap/sitemap-index.xml',
        'sitemap/sitemap.xml',
        '.sitemap.xml',
        'sitemap1.xml',
        'sitemap/sitemap1.xml',
        'sitemap_index.xml',
    ]
    sitemaps_found = []

    async with aiohttp.ClientSession() as session:
        tasks = []
        for sitemap in potential_sitemaps:
            sitemap_url = urljoin(base_url, sitemap)
            tasks.append(fetch_sitemap(session, sitemap_url))
        
        results = await asyncio.gather(*tasks)

    for sitemap_url, status in results:
        if status == 200:
            sitemaps_found.append(sitemap_url)

    return sitemaps_found


async def fetch_sitemap(session, url):
    try:
        async with session.get(url, timeout=DEFAULT_TIMEOUT) as response:
            return url, response.status
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return url, None


async def parse_sitemap(sitemap_url, parsed_urls=set(), sitemaps_to_parse=set()):
    urls_info = []
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(sitemap_url, timeout=DEFAULT_TIMEOUT) as response:
                response.raise_for_status()
                content_type = response.headers.get('Content-Type', '')
                content = await response.text()
                if 'xml' in content_type or 'html' in content_type:
                    soup = BeautifulSoup(content, 'html.parser')  # Use html.parser for XML parsing
                    # Check if it's a sitemap index
                    sitemap_tags = soup.find_all('sitemap')
                    if sitemap_tags:
                        for sitemap in sitemap_tags:
                            loc = sitemap.find('loc')
                            if loc and loc.text not in sitemaps_to_parse:
                                sitemaps_to_parse.add(loc.text)
                                urls_info.extend(await parse_sitemap(loc.text, parsed_urls, sitemaps_to_parse))
                    else:
                        # It's a regular sitemap
                        url_tags = soup.find_all('url')
                        for url_tag in url_tags:
                            loc = url_tag.find('loc')
                            if loc and loc.text not in parsed_urls:
                                parsed_urls.add(loc.text)
                                url_info = {
                                    'loc': loc.text,
                                    'lastmod': url_tag.find('lastmod').text if url_tag.find('lastmod') else 'N/A',
                                    'changefreq': url_tag.find('changefreq').text if url_tag.find('changefreq') else 'N/A',
                                    'priority': url_tag.find('priority').text if url_tag.find('priority') else 'N/A',
                                }
                                urls_info.append(url_info)
                elif 'text/plain' in content_type:
                    # It's a plain text sitemap
                    urls = content.strip().split('\n')
                    for url in urls:
                        url = url.strip()
                        if url and url not in parsed_urls:
                            parsed_urls.add(url)
                            url_info = {'loc': url, 'lastmod': 'N/A', 'changefreq': 'N/A', 'priority': 'N/A'}
                            urls_info.append(url_info)
                else:
                    console.print(Fore.YELLOW + f"[!] Unsupported sitemap content type at {sitemap_url}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            console.print(Fore.RED + f"[!] Error retrieving sitemap from {sitemap_url}: {e}")
    return urls_info


async def check_url_status(session, url_info):
    try:
        async with session.head(url_info['loc'], timeout=DEFAULT_TIMEOUT, allow_redirects=True) as response:
            url_info['status_code'] = response.status
    except (aiohttp.ClientError, asyncio.TimeoutError):
        url_info['status_code'] = 'Error'


async def check_all_urls_status(urls_info):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url_info in urls_info:
            tasks.append(check_url_status(session, url_info))
        await asyncio.gather(*tasks)


def display_sitemap(urls_info, analysis):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("URL", style="green", justify="left")
    table.add_column("Status", style="cyan")
    table.add_column("Last Modified", style="yellow")
    table.add_column("Changefreq", style="blue")
    table.add_column("Priority", style="red")

    for url_info in urls_info:
        status = str(url_info.get('status_code', 'N/A'))
        table.add_row(
            url_info['loc'],
            status,
            url_info.get('lastmod', 'N/A'),
            url_info.get('changefreq', 'N/A'),
            url_info.get('priority', 'N/A'),
        )
    console.print(table)
    console.print(Fore.GREEN + f"\nTotal URLs: {analysis['total_urls']}")
    console.print(Fore.YELLOW + f"Unique URLs: {analysis['unique_urls']}")
    console.print(Fore.RED + f"Broken URLs: {analysis['broken_urls']}")


def analyze_sitemap(urls_info):
    analysis = {
        'total_urls': len(urls_info),
        'unique_urls': len(set(u['loc'] for u in urls_info)),
        'broken_urls': sum(1 for u in urls_info if str(u.get('status_code')).startswith('4') or str(u.get('status_code')).startswith('5') or u.get('status_code') == 'Error'),
    }
    return analysis


async def main(target):
    banner()
    target = convert_to_url(target)
    console.print(Fore.WHITE + f"[*] Fetching sitemaps for: {target}")

    sitemaps = await get_sitemap_urls(target)
    if not sitemaps:
        console.print(Fore.RED + "[!] No sitemaps found.")
        return

    console.print(Fore.GREEN + f"[*] Found {len(sitemaps)} sitemap(s).")

    all_urls_info = []
    parsed_urls = set()
    sitemaps_to_parse = set(sitemaps)

    # Parse all sitemaps
    while sitemaps_to_parse:
        sitemap_url = sitemaps_to_parse.pop()
        console.print(Fore.WHITE + f"[*] Parsing sitemap: {sitemap_url}")
        urls_info = await parse_sitemap(sitemap_url, parsed_urls, sitemaps_to_parse)
        all_urls_info.extend(urls_info)

    if not all_urls_info:
        console.print(Fore.YELLOW + "[!] No URLs found in the sitemap(s).")
        return

    console.print(Fore.WHITE + "[*] Checking status codes for URLs...")
    await check_all_urls_status(all_urls_info)

    analysis = analyze_sitemap(all_urls_info)
    display_sitemap(all_urls_info, analysis)
    console.print(Fore.WHITE + "[*] Sitemap analysis completed.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            asyncio.run(main(target))
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a URL.")
        sys.exit(1)
