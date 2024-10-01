import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import time
from bs4 import BeautifulSoup

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input  
from config.settings import DEFAULT_TIMEOUT  

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
           Argus - Advanced Firewall Detection
    =============================================
    """)

def detect_firewall(url):
    detection_results = set()

    try:
        # Basic response analysis
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        headers = response.headers
        status_code = response.status_code
        response_body = response.text

        if 'Server' in headers and 'cloudflare' in headers['Server'].lower():
            detection_results.add("Cloudflare Firewall Detected")
        elif 'X-Akamai' in headers:
            detection_results.add("Akamai Firewall Detected")
        elif 'x-sucuri-id' in headers:
            detection_results.add("Sucuri Firewall Detected")
        elif 'x-amz-cf-id' in headers or 'x-amz-request-id' in headers:
            detection_results.add("AWS Shield Detected")
        elif 'x-cdn' in headers and 'imperva' in headers['x-cdn'].lower():
            detection_results.add("Imperva Firewall Detected")
        elif 'X-CDN' in headers and 'Incapsula' in headers['X-CDN']:
            detection_results.add("Incapsula Firewall Detected")
        elif 'X-Proxy-Id' in headers or 'X-Proxy-Security' in headers:
            detection_results.add("F5 BIG-IP Detected")
        elif 'X-Cache' in headers and 'BunnyCDN' in headers['X-Cache']:
            detection_results.add("BunnyCDN Firewall Detected")
        elif 'X-Powered-By' in headers and 'Palo Alto' in headers['X-Powered-By']:
            detection_results.add("Palo Alto Firewall Detected")
        elif 'Server' in headers and 'f5' in headers['Server'].lower():
            detection_results.add("F5 Networks Firewall Detected")
        elif 'Server' in headers and 'Barracuda' in headers['Server']:
            detection_results.add("Barracuda WAF Detected")
        elif 'X-WAF' in headers or 'X-Wallarm' in headers:
            detection_results.add("Wallarm WAF Detected")
        elif status_code == 403:
            detection_results.add("Possible WAF Detected - Received 403 Forbidden")
        
        if response.elapsed.total_seconds() > 5:
            detection_results.add("Possible Rate Limiting Detected - WAF Protection")

        if 'captcha' in response_body.lower() or 'access denied' in response_body.lower():
            detection_results.add("Possible CAPTCHA Detected - WAF Protection")

        if '<title>Access Denied</title>' in response_body:
            detection_results.add("Access Denied Page Detected - Possible WAF")

        soup = BeautifulSoup(response_body, 'html.parser')
        if soup.find('div', {'id': 'challenge'}):
            detection_results.add("JavaScript Challenge Detected - Possible Cloudflare or Similar WAF")

        # Probing unusual paths
        unusual_paths = ["/admin", "/login", "/phpmyadmin"]
        for path in unusual_paths:
            probe_url = f"{url.rstrip('/')}{path}"
            probe_response = requests.get(probe_url, timeout=DEFAULT_TIMEOUT)
            if probe_response.status_code == 403 or 'forbidden' in probe_response.text.lower():
                detection_results.add(f"Potential WAF Blocking Access to Sensitive Path ({path})")

        # Using non-standard HTTP methods
        non_standard_methods = ["OPTIONS", "TRACE", "PUT"]
        for method in non_standard_methods:
            probe_response = requests.request(method, url, timeout=DEFAULT_TIMEOUT)
            if probe_response.status_code in [405, 501]:
                detection_results.add(f"{method} Method Blocked - Possible WAF Behavior")

        # Analyzing responses for content alterations or challenges
        altered_headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        }
        altered_response = requests.get(url, headers=altered_headers, timeout=DEFAULT_TIMEOUT)
        if altered_response.status_code != status_code:
            detection_results.add("Different Response with Altered Headers - Possible WAF Behavior")
        
        if 'challenge' in altered_response.text.lower():
            detection_results.add("Possible Challenge Detected with Altered Headers")

        time.sleep(1)

        return ", ".join(detection_results) if detection_results else "No Recognized Firewall Detected"

    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving firewall information: {e}")
        return None

def display_firewall_detection(firewall_info):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Firewall Status", style="cyan", justify="left")
    table.add_column("Details", style="green", justify="left")
    table.add_row(firewall_info, "Detected through HTTP headers, response behavior, non-standard methods, and content analysis")
    console.print(table)

def main(target):
    banner()
    target = clean_domain_input(target)
    console.print(Fore.WHITE + f"[*] Detecting firewall for: {target}")

    firewall_info = detect_firewall(target)
    if firewall_info:
        display_firewall_detection(firewall_info)
    else:
        console.print(Fore.RED + "[!] No firewall information found.")
    
    console.print(Fore.WHITE + "[*] Firewall detection completed.")

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
