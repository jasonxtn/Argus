import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
from urllib.parse import urljoin, urlparse

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

SOCIAL_MEDIA_DOMAINS = {
    'facebook.com': 'Facebook',
    'twitter.com': 'Twitter',
    'instagram.com': 'Instagram',
    'linkedin.com': 'LinkedIn',
    'youtube.com': 'YouTube',
    'pinterest.com': 'Pinterest',
    'tiktok.com': 'TikTok',
    'snapchat.com': 'Snapchat',
    'github.com': 'GitHub'
}

def banner():
    console.print(Fore.GREEN + """
=============================================
     Argus - Social Media Presence Check
=============================================
""")

def convert_to_url(target):
    parsed = urlparse(target)
    if not parsed.scheme:
        return f"http://{target}"
    return target

def detect_social_media_from_page(domain):
    social_media_profiles = []
    try:
        response = requests.get(domain, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            for sm_domain, platform in SOCIAL_MEDIA_DOMAINS.items():
                if sm_domain in href:
                    profile_url = href
                    if not urlparse(href).netloc:
                        profile_url = urljoin(domain, href)
                    social_media_profiles.append({'platform': platform, 'url': profile_url})
                    console.print(f"[+] Found {platform} profile: {profile_url}")
        social_media_profiles = [dict(t) for t in {tuple(d.items()) for d in social_media_profiles}]
        return social_media_profiles
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error detecting social media profiles from page source: {e}")
        return []

def search_social_media_using_duckduckgo(domain):
    social_media_profiles = []
    search_url = f"https://duckduckgo.com/html/?q=site:{domain}+social+media"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(search_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            for sm_domain, platform in SOCIAL_MEDIA_DOMAINS.items():
                if sm_domain in href:
                    social_media_profiles.append({'platform': platform, 'url': href})
                    console.print(f"[+] Found {platform} profile using DuckDuckGo: {href}")
        social_media_profiles = [dict(t) for t in {tuple(d.items()) for d in social_media_profiles}]
        return social_media_profiles
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error detecting social media profiles using DuckDuckGo: {e}")
        return []

def detect_social_media_from_internal_links(domain):
    social_media_profiles = []
    try:
        response = requests.get(domain, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            for sm_domain, platform in SOCIAL_MEDIA_DOMAINS.items():
                if sm_domain in href:
                    profile_url = href
                    if not urlparse(href).netloc:
                        profile_url = urljoin(domain, href)
                    social_media_profiles.append({'platform': platform, 'url': profile_url})
                    console.print(f"[+] Found {platform} profile from internal links: {profile_url}")
        social_media_profiles = [dict(t) for t in {tuple(d.items()) for d in social_media_profiles}]
        return social_media_profiles
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error detecting social media profiles from internal links: {e}")
        return []

def detect_social_media_from_metadata(domain):
    social_media_profiles = []
    try:
        response = requests.get(domain, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        meta_tags = soup.find_all('meta', property=True, content=True)
        for tag in meta_tags:
            content = tag['content']
            for sm_domain, platform in SOCIAL_MEDIA_DOMAINS.items():
                if sm_domain in content:
                    social_media_profiles.append({'platform': platform, 'url': content})
                    console.print(f"[+] Found {platform} profile from metadata: {content}")
        social_media_profiles = [dict(t) for t in {tuple(d.items()) for d in social_media_profiles}]
        return social_media_profiles
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error detecting social media profiles from metadata: {e}")
        return []

def search_social_media_using_google(domain):
    social_media_profiles = []
    search_url = f"https://www.google.com/search?q=site:{domain}+social+media"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(search_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            for sm_domain, platform in SOCIAL_MEDIA_DOMAINS.items():
                if sm_domain in href:
                    social_media_profiles.append({'platform': platform, 'url': href})
                    console.print(f"[+] Found {platform} profile using Google search: {href}")
        social_media_profiles = [dict(t) for t in {tuple(d.items()) for d in social_media_profiles}]
        return social_media_profiles
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error detecting social media profiles using Google search: {e}")
        return []

def display_social_media_profiles(profiles):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Platform", style="cyan", justify="left")
    table.add_column("Profile URL", style="green", justify="left", overflow="fold")
    if profiles:
        for profile in profiles:
            table.add_row(profile.get("platform"), profile.get("url"))
    else:
        table.add_row("No Data", "No social media profiles found")
    console.print(table)

def main(target):
    banner()
    console.print(Fore.WHITE + "[*] Please wait, this may take some time...")
    url = convert_to_url(target)
    console.print(Fore.WHITE + f"[*] Detecting social media presence for: {url}")
    domain = urlparse(url).netloc

    social_media_profiles = []

    social_media_profiles += detect_social_media_from_page(url)
    if not social_media_profiles:
        console.print(Fore.YELLOW + "[!] No social media profiles found in the HTML page source. Trying DuckDuckGo search...")
        social_media_profiles += search_social_media_using_duckduckgo(domain)

    if not social_media_profiles:
        console.print(Fore.YELLOW + "[!] No social media profiles found using DuckDuckGo. Trying internal page links...")
        social_media_profiles += detect_social_media_from_internal_links(url)

    if not social_media_profiles:
        console.print(Fore.YELLOW + "[!] No social media profiles found in internal links. Trying metadata...")
        social_media_profiles += detect_social_media_from_metadata(url)

    if not social_media_profiles:
        console.print(Fore.YELLOW + "[!] No social media profiles found in metadata. Trying Google search...")
        social_media_profiles += search_social_media_using_google(domain)

    display_social_media_profiles(social_media_profiles)
    console.print(Fore.WHITE + "[*] Social media presence check completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
