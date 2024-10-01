import os
import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, Style, init
import re
import argparse
from urllib.parse import urljoin, urlparse

init(autoreset=True)
console = Console()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url, log_message
from config.settings import DEFAULT_TIMEOUT

GDPR_KEYWORDS = [
    "gdpr", "general data protection regulation", "data controller",
    "data processor", "consent", "data subject", "data protection officer",
    "privacy rights", "right to be forgotten", "data breach"
]

PRIVACY_KEYWORDS = [
    "personal data", "data collection", "data usage", "information we collect",
    "how we use your information", "data sharing", "third-party services",
    "data retention", "user rights", "privacy statement"
]

COOKIE_KEYWORDS = [
    "cookie policy", "cookies", "tracking technologies", "third-party cookies",
    "cookie consent", "manage cookies", "cookie settings"
]

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - Privacy & GDPR Compliance
    =============================================
    """)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Argus - Check Privacy Policy, GDPR Compliance, and Cookie Policy of a Website"
    )
    parser.add_argument(
        'url',
        type=str,
        help='Target website URL or domain (e.g., https://example.com or example.com)'
    )
    parser.add_argument(
        '--log',
        action='store_true',
        help='Enable logging to privacy_gdpr_compliance.log'
    )
    return parser.parse_args()

def validate_url(url):
    cleaned_url = clean_url(url)
    parsed = urlparse(cleaned_url)
    if not parsed.scheme or not parsed.netloc:
        console.print(Fore.RED + "[!] Invalid URL provided.")
        sys.exit(1)
    return cleaned_url

def find_policy_links(session, url):
    try:
        response = session.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error fetching the homepage: {e}")
        log_message("privacy_gdpr_compliance.log", f"Error fetching the homepage: {e}")
        return None, None, None

    soup = BeautifulSoup(response.text, 'html.parser')

    privacy_link = None
    gdpr_link = None
    cookie_link = None

    privacy_texts = [
        'privacy policy', 'privacy statement', 'privacy', 'data protection policy'
    ]

    gdpr_texts = [
        'gdpr', 'gdpr compliance', 'data protection regulation', 'general data protection regulation'
    ]

    cookie_texts = [
        'cookie policy', 'cookies', 'tracking technologies', 'third-party cookies',
        'cookie consent', 'manage cookies', 'cookie settings'
    ]

    for a_tag in soup.find_all('a', href=True):
        link_text = a_tag.get_text(strip=True).lower()
        if not privacy_link and any(text in link_text for text in privacy_texts):
            privacy_link = urljoin(url, a_tag['href'])
        if not gdpr_link and any(text in link_text for text in gdpr_texts):
            gdpr_link = urljoin(url, a_tag['href'])
        if not cookie_link and any(text in link_text for text in cookie_texts):
            cookie_link = urljoin(url, a_tag['href'])
        if privacy_link and gdpr_link and cookie_link:
            break

    if not privacy_link:
        privacy_link = urljoin(url, "/privacy-policy")
    if not gdpr_link:
        gdpr_link = urljoin(url, "/gdpr-compliance")
    if not cookie_link:
        cookie_link = urljoin(url, "/cookie-policy")

    return privacy_link, gdpr_link, cookie_link

def check_policy(session, policy_url, policy_type, keywords):
    try:
        response = session.get(policy_url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            content = response.text
            matches = [keyword for keyword in keywords if keyword in content.lower()]
            if matches:
                console.print(Fore.GREEN + f"[+] {policy_type} Found: {policy_url}")
                console.print(Fore.GREEN + f"[+] {policy_type} Keywords Found: {', '.join(matches)}")
                log_message("privacy_gdpr_compliance.log", f"{policy_type} Found: {policy_url} | Keywords: {', '.join(matches)}")
                return "Found", True
            else:
                console.print(Fore.YELLOW + f"[!] {policy_type} Found but no relevant keywords detected.")
                log_message("privacy_gdpr_compliance.log", f"{policy_type} Found: {policy_url} | No relevant keywords detected.")
                return "Found", False
        else:
            console.print(Fore.RED + f"[!] {policy_type} Not Found at {policy_url} (Status Code: {response.status_code})")
            log_message("privacy_gdpr_compliance.log", f"{policy_type} Not Found at {policy_url} (Status Code: {response.status_code})")
            return "Not Found", False
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving {policy_type} at {policy_url}: {e}")
        log_message("privacy_gdpr_compliance.log", f"Error retrieving {policy_type} at {policy_url}: {e}")
        return "Error", False

def display_results(privacy_result, gdpr_result, cookie_result):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan", justify="left")
    table.add_column("Result", style="green", justify="left")
    table.add_column("Compliance", style="yellow", justify="left")

    table.add_row("Privacy Policy", privacy_result[0], "Yes" if privacy_result[1] else "No")
    table.add_row("GDPR Compliance", gdpr_result[0], "Yes" if gdpr_result[1] else "No")
    table.add_row("Cookie Policy", cookie_result[0], "Yes" if cookie_result[1] else "No")

    console.print(table)

def main(target_url, enable_logging):
    banner()
    console.print(Fore.WHITE + f"[*] Checking Privacy Policy, GDPR Compliance, and Cookie Policy for: {target_url}")

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/91.0.4472.124 Safari/537.36'
    })

    privacy_url, gdpr_url, cookie_url = find_policy_links(session, target_url)

    console.print(Fore.WHITE + f"[*] Privacy Policy URL: {privacy_url}")
    console.print(Fore.WHITE + f"[*] GDPR Compliance URL: {gdpr_url}")
    console.print(Fore.WHITE + f"[*] Cookie Policy URL: {cookie_url}")

    privacy_result = check_policy(session, privacy_url, "Privacy Policy", PRIVACY_KEYWORDS)
    gdpr_result = check_policy(session, gdpr_url, "GDPR Compliance", GDPR_KEYWORDS)
    cookie_result = check_policy(session, cookie_url, "Cookie Policy", COOKIE_KEYWORDS)

    display_results(privacy_result, gdpr_result, cookie_result)

    if enable_logging:
        log_message("privacy_gdpr_compliance.log",
                    f"Checked URL: {target_url}\n"
                    f"Privacy Policy: {privacy_result}\n"
                    f"GDPR Compliance: {gdpr_result}\n"
                    f"Cookie Policy: {cookie_result}\n")

    console.print(Fore.WHITE + "[*] Privacy & GDPR compliance check completed.")

if __name__ == "__main__":
    args = parse_arguments()
    target = validate_url(args.url)
    main(target, args.log)
