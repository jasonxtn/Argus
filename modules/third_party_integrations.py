import os
import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import logging

required_modules = ['requests', 'bs4', 'rich', 'colorama']
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print(Fore.RED + "[!] Missing required modules: " + ', '.join(missing_modules))
    print(Fore.YELLOW + "Please install them using: pip install -r requirements.txt")
    sys.exit(1)

init(autoreset=True)
console = Console()

log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, 'third_party_integrations.log')
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def banner():
    print(Fore.WHITE + """
=============================================
    Argus - Third-Party Integrations Check
=============================================
""")

def detect_by_html_content(url):
    integrations = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            if 'google-analytics' in src:
                integrations.append({'Integration': 'Google Analytics', 'Details': 'Tracking'})
            elif 'facebook' in src:
                integrations.append({'Integration': 'Facebook SDK', 'Details': 'Social Media Integration'})
            elif 'linkedin' in src:
                integrations.append({'Integration': 'LinkedIn Insights', 'Details': 'Social Media Integration'})
            elif 'twitter' in src:
                integrations.append({'Integration': 'Twitter Widgets', 'Details': 'Social Media Integration'})
            elif 'stripe' in src:
                integrations.append({'Integration': 'Stripe', 'Details': 'Payment Gateway'})
            elif 'paypal' in src:
                integrations.append({'Integration': 'PayPal', 'Details': 'Payment Gateway'})
            elif 'hotjar' in src:
                integrations.append({'Integration': 'Hotjar', 'Details': 'User Behavior Analytics'})
            elif 'intercom' in src:
                integrations.append({'Integration': 'Intercom', 'Details': 'Customer Support'})
            elif 'cloudflare' in src:
                integrations.append({'Integration': 'Cloudflare', 'Details': 'Security and CDN'})
            elif 'disqus' in src:
                integrations.append({'Integration': 'Disqus', 'Details': 'Commenting System'})
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error retrieving HTML content: {e}")
        logging.error(f"Error retrieving HTML content: {e}")
    return integrations

def detect_by_headers(url):
    integrations = []
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        headers = response.headers
        if 'x-amz-request-id' in headers:
            integrations.append({'Integration': 'Amazon S3', 'Details': 'Cloud Storage'})
        if 'cf-ray' in headers:
            integrations.append({'Integration': 'Cloudflare', 'Details': 'Content Delivery Network (CDN)'})
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'express' in powered_by:
                integrations.append({'Integration': 'Express.js', 'Details': 'Web Framework'})
            elif 'asp.net' in powered_by:
                integrations.append({'Integration': 'ASP.NET', 'Details': 'Web Framework'})
            elif 'php' in powered_by:
                integrations.append({'Integration': 'PHP', 'Details': 'Backend Language'})
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error retrieving HTTP headers: {e}")
        logging.error(f"Error retrieving HTTP headers: {e}")
    return integrations

def detect_by_meta_tags(url):
    integrations = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            if meta.get('name') == 'generator' and 'WordPress' in meta.get('content', ''):
                integrations.append({'Integration': 'WordPress', 'Details': 'CMS'})
            elif meta.get('name') == 'viewport' and 'shopify' in response.text.lower():
                integrations.append({'Integration': 'Shopify', 'Details': 'E-commerce Platform'})
        inline_scripts = soup.find_all('script')
        for script in inline_scripts:
            if script.string and 'google-analytics' in script.string:
                integrations.append({'Integration': 'Google Analytics', 'Details': 'Tracking'})
            elif script.string and 'fbq' in script.string:
                integrations.append({'Integration': 'Facebook Pixel', 'Details': 'Advertising and Tracking'})
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error retrieving meta tags: {e}")
        logging.error(f"Error retrieving meta tags: {e}")
    return integrations

def display_third_party_integrations(integrations):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Integration", style="cyan", justify="left")
    table.add_column("Details", style="green")
    seen = set()
    unique_integrations = []
    for integration in integrations:
        integration_id = (integration['Integration'], integration['Details'])
        if integration_id not in seen:
            seen.add(integration_id)
            unique_integrations.append(integration)
    for integration in unique_integrations:
        table.add_row(integration['Integration'], integration['Details'])
    console.print(table)

def save_results(integrations, target):
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Results')
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    filename = os.path.join(results_dir, f"third_party_integrations_{target.replace('://', '_').replace('/', '_')}.txt")
    try:
        with open(filename, 'w') as f:
            for integration in integrations:
                f.write(f"Integration: {integration['Integration']}\n")
                f.write(f"Details: {integration['Details']}\n")
                f.write('---\n')
        print(Fore.GREEN + f"[+] Results saved to {filename}")
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving results: {e}")
        logging.error(f"Error saving results: {e}")

def main(target):
    banner()
    print(Fore.WHITE + f"[*] Detecting third-party integrations for: {target}")
    logging.info(f"Started third-party integrations detection for: {target}")
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    integrations = []
    print(Fore.CYAN + "[*] Analyzing HTML content...")
    integrations += detect_by_html_content(target)
    print(Fore.CYAN + "[*] Analyzing HTTP headers...")
    integrations += detect_by_headers(target)
    print(Fore.CYAN + "[*] Analyzing meta tags and JavaScript references...")
    integrations += detect_by_meta_tags(target)
    if integrations:
        print(Fore.GREEN + "[+] Third-party integrations detected:")
        display_third_party_integrations(integrations)
        save_results(integrations, target)
    else:
        console.print(Fore.RED + "[!] No third-party integrations found.")
        logging.info("No third-party integrations found.")
    print(Fore.CYAN + "[*] Third-party integrations check completed.")
    logging.info("Third-party integrations check completed.")

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            target = sys.argv[1]
            main(target)
        else:
            console.print(Fore.YELLOW + "[*] Please enter the target domain or URL.")
            target = input(Fore.WHITE + "Target: ")
            if target:
                main(target)
            else:
                console.print(Fore.RED + "[!] No target provided. Exiting.")
                sys.exit(1)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        logging.warning("Process interrupted by user.")
        sys.exit(1)
