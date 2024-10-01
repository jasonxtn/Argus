import os
import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import argparse
from urllib.parse import urljoin, urlparse
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url, log_message
from config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

SECURITY_TXT_FIELDS = {
    "Contact": {"required": True, "pattern": re.compile(r'^mailto:|^https?://')},
    "Encryption": {"required": False, "pattern": re.compile(r'^https?://')},
    "Acknowledgements": {"required": False, "pattern": re.compile(r'^https?://')},
    "Preferred-Languages": {"required": False, "pattern": re.compile(r'^[a-zA-Z-]+(,[a-zA-Z-]+)*$')},
    "Expires": {"required": False, "pattern": re.compile(r'^\d{4}-\d{2}-\d{2}$')},
    "Policy": {"required": False, "pattern": re.compile(r'^https?://')},
    "Hiring": {"required": False, "pattern": re.compile(r'^https?://')},
}

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - Security.txt Detection
    =============================================
    """)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Argus - Security.txt Detection and Analysis")
    parser.add_argument('url', type=str, help='Target website URL or domain (e.g., https://example.com or example.com)')
    parser.add_argument('--log', action='store_true', help='Enable logging to security_txt_detection.log')
    return parser.parse_args()

def validate_url(url):
    cleaned_url = clean_url(url)
    parsed = urlparse(cleaned_url)
    if not parsed.scheme or not parsed.netloc:
        console.print(Fore.RED + "[!] Invalid URL provided.")
        sys.exit(1)
    return cleaned_url

def get_security_txt(url):
    security_txt_url = urljoin(url, '/.well-known/security.txt')
    try:
        response = requests.get(security_txt_url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code == 200:
            return response.text
        return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving security.txt: {e}")
        return None

def parse_security_txt(content):
    fields = {}
    for line in content.splitlines():
        if line.startswith('#') or not line.strip():
            continue
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key in SECURITY_TXT_FIELDS:
                fields[key] = value
    return fields

def analyze_fields(fields):
    analysis = {}
    for field, rules in SECURITY_TXT_FIELDS.items():
        value = fields.get(field)
        if value:
            if rules["pattern"].search(value):
                analysis[field] = {"status": "Valid", "value": value}
            else:
                analysis[field] = {"status": "Invalid Format", "value": value}
        else:
            if rules["required"]:
                analysis[field] = {"status": "Missing", "value": "-"}
            else:
                analysis[field] = {"status": "Not Provided", "value": "-"}
    return analysis

def validate_email(email):
    pattern = re.compile(r'^mailto:([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)$')
    match = pattern.match(email)
    if match:
        return match.group(1)
    return None

def validate_url_field(url):
    parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])

def advanced_analysis(analysis):
    for field, result in analysis.items():
        if field == "Contact" and result["status"] == "Valid":
            contact_email = validate_email(result["value"])
            if contact_email:
                analysis[field]["details"] = f"Email: {contact_email}"
            elif validate_url_field(result["value"]):
                analysis[field]["details"] = f"URL: {result['value']}"
            else:
                analysis[field]["details"] = "Invalid Contact Format"
        elif field in ["Encryption", "Acknowledgements", "Policy", "Hiring"] and result["status"] == "Valid":
            if validate_url_field(result["value"]):
                analysis[field]["details"] = "Valid URL"
            else:
                analysis[field]["details"] = "Invalid URL Format"
        elif field == "Preferred-Languages" and result["status"] == "Valid":
            languages = [lang.strip() for lang in result["value"].split(',')]
            analysis[field]["details"] = f"Languages: {', '.join(languages)}"
        elif field == "Expires" and result["status"] == "Valid":
            analysis[field]["details"] = f"Expiration Date: {result['value']}"
        else:
            analysis[field]["details"] = "-"
    return analysis

def display_analysis(analysis):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", justify="left")
    table.add_column("Status", style="green", justify="left")
    table.add_column("Details", style="yellow", justify="left")
    for field, result in analysis.items():
        status = Fore.GREEN + result["status"] if result["status"] == "Valid" else (Fore.RED + result["status"] if "Invalid" in result["status"] or "Missing" in result["status"] else Fore.YELLOW + result["status"])
        table.add_row(field, status, result.get("details", "-"))
    console.print(table)

def main(target, enable_logging):
    banner()
    url = validate_url(target)
    console.print(Fore.WHITE + f"[*] Fetching security.txt for: {url}")
    security_txt = get_security_txt(url)
    if security_txt:
        fields = parse_security_txt(security_txt)
        analysis = analyze_fields(fields)
        analysis = advanced_analysis(analysis)
        display_analysis(analysis)
        if enable_logging:
            log_entry = f"URL: {url}\n"
            for field, result in analysis.items():
                log_entry += f"{field}: {result['status']} | {result['details']}\n"
            log_message("security_txt_detection.log", log_entry)
    else:
        console.print(Fore.RED + "[!] No security.txt file found.")
        if enable_logging:
            log_message("security_txt_detection.log", f"URL: {url}\nsecurity.txt: Not Found\n")
    console.print(Fore.WHITE + "[*] Security.txt detection and analysis completed.")

if __name__ == "__main__":
    args = parse_arguments()
    try:
        main(args.url, args.log)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
