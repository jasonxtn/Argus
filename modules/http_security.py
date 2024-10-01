import sys,os
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import json
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, clean_url, ensure_url_format

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced HTTP Security Headers Check
    =============================================
    """)

def get_headers(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.headers, response.text
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving headers: {e}")
        return None, None

def display_headers(headers):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Header", style="cyan", justify="left")
    table.add_column("Value", style="green")
    for header, value in headers.items():
        table.add_row(header, value)
    console.print(table)

def analyze_security_headers(headers):
    security_headers = {
        "Content-Security-Policy": "Not Set",
        "Strict-Transport-Security": "Not Set",
        "X-Content-Type-Options": "Not Set",
        "X-Frame-Options": "Not Set",
        "X-XSS-Protection": "Not Set",
        "Referrer-Policy": "Not Set",
        "Permissions-Policy": "Not Set"
    }
    for header in security_headers:
        if header in headers:
            security_headers[header] = "Configured"
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Security Header", style="cyan", justify="left")
    table.add_column("Status", style="green")
    for header, status in security_headers.items():
        table.add_row(header, status)
    console.print(table)
    missing = [header for header, status in security_headers.items() if status == "Not Set"]
    if missing:
        console.print(Fore.YELLOW + f"[!] Missing Security Headers: {', '.join(missing)}")
    else:
        console.print(Fore.GREEN + "[+] All critical security headers are properly configured.")

def identify_server_technology(headers):
    server = headers.get("Server", "Unknown")
    technology = "Unknown"
    if "nginx" in server.lower():
        technology = "Nginx Web Server"
    elif "apache" in server.lower():
        technology = "Apache Web Server"
    elif "iis" in server.lower():
        technology = "Microsoft IIS"
    elif "cloudflare" in server.lower():
        technology = "Cloudflare CDN"
    console.print(Fore.YELLOW + "[*] Detecting server technology...")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Server", style="cyan", justify="left")
    table.add_column("Detected Technology", style="green")
    table.add_row(server, technology)
    console.print(table)

def scan_vulnerabilities(headers):
    vulnerabilities = []
    if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        vulnerabilities.append("X-Content-Type-Options is not set to 'nosniff'")
    if "Strict-Transport-Security" in headers:
        if "max-age=0" in headers["Strict-Transport-Security"]:
            vulnerabilities.append("Strict-Transport-Security max-age is set to 0")
    if "Content-Security-Policy" in headers:
        if "default-src 'self'" not in headers["Content-Security-Policy"]:
            vulnerabilities.append("Content-Security-Policy is not restrictive enough")
    if headers.get("X-Frame-Options", "").upper() not in ["DENY", "SAMEORIGIN"]:
        vulnerabilities.append("X-Frame-Options is not set to 'DENY' or 'SAMEORIGIN'")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Vulnerability", style="cyan", justify="left")
    table.add_column("Issue", style="red")
    for vuln in vulnerabilities:
        table.add_row("Security Issue", vuln)
    if vulnerabilities:
        console.print(table)
    else:
        console.print(Fore.GREEN + "[+] No vulnerabilities detected based on HTTP headers.")

def analyze_cookies(headers):
    cookies = headers.get("Set-Cookie")
    if not cookies:
        console.print(Fore.YELLOW + "[!] No cookies found.")
        return
    console.print(Fore.YELLOW + "[*] Analyzing cookies for security flags...")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Cookie", style="cyan", justify="left")
    table.add_column("Attributes", style="green")
    cookies = cookies.split(',')
    for cookie in cookies:
        cookie = cookie.strip()
        parts = cookie.split(';')
        name_value = parts[0]
        attributes = [attr.strip() for attr in parts[1:]]
        security_flags = []
        for attr in attributes:
            if attr.lower() == "secure":
                security_flags.append("Secure")
            if attr.lower() == "httponly":
                security_flags.append("HttpOnly")
            if attr.lower().startswith("samesite"):
                security_flags.append(attr)
        table.add_row(name_value, ", ".join(security_flags) if security_flags else "None")
    console.print(table)

def detect_frameworks(response_text):
    frameworks = {
        "WordPress": "wp-content",
        "Joomla": "Joomla!",
        "Drupal": "Drupal.settings",
        "Django": "csrftoken",
        "Ruby on Rails": "Rails",
        "Laravel": "laravel_session"
    }
    detected = []
    for framework, signature in frameworks.items():
        if signature in response_text:
            detected.append(framework)
    if detected:
        console.print(Fore.GREEN + f"[+] Detected Frameworks: {', '.join(detected)}")
    else:
        console.print(Fore.YELLOW + "[!] No common frameworks detected.")

def main(target):
    banner()
    target = clean_url(clean_domain_input(target))
    console.print(Fore.WHITE + f"[*] Fetching HTTP headers for: {target}")
    headers, response_text = get_headers(target)
    if headers:
        console.print(Fore.YELLOW + "[*] Displaying HTTP headers...")
        display_headers(headers)
        console.print(Fore.YELLOW + "[*] Analyzing security headers...")
        analyze_security_headers(headers)
        identify_server_technology(headers)
        console.print(Fore.YELLOW + "[*] Scanning for vulnerabilities based on headers...")
        scan_vulnerabilities(headers)
        console.print(Fore.YELLOW + "[*] Analyzing cookies for security flags...")
        analyze_cookies(headers)
        console.print(Fore.YELLOW + "[*] Detecting frameworks based on response content...")
        detect_frameworks(response_text)
    else:
        console.print(Fore.RED + "[!] No headers found.")
    console.print(Fore.WHITE + "[*] HTTP header analysis completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            target = sys.argv[1]
            main(target)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
