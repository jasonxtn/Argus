import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import time
import re

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10  # You can adjust the timeout as needed

def clean_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return 'http://' + url
    return url

def banner():
    console.print(Fore.GREEN + """
=============================================
       Argus - Quality Metrics Check
=============================================
""")

def is_minified(content):
    # Simple heuristic to check if content is minified
    if len(content) == 0:
        return False
    ratio = content.count('\n') / len(content)
    return ratio < 0.01  # Less than 1% newlines

def get_quality_metrics(url):
    metrics = {}
    try:
        start_time = time.time()
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        end_time = time.time()
        metrics['load_time'] = end_time - start_time
        metrics['status_code'] = response.status_code
        metrics['page_size'] = len(response.content)
        metrics['compressed'] = response.headers.get('Content-Encoding') in ['gzip', 'br']
        metrics['https'] = urlparse(url).scheme == 'https'
        
        # Parse the content
        soup = BeautifulSoup(response.content, 'html.parser')
        metrics['num_images'] = len(soup.find_all('img'))
        metrics['num_scripts'] = len(soup.find_all('script'))
        metrics['num_stylesheets'] = len(soup.find_all('link', rel='stylesheet'))
        metrics['num_links'] = len(soup.find_all('a'))
        metrics['mobile_friendly'] = bool(soup.find('meta', attrs={'name': 'viewport'}))
        
        # Count total requests
        metrics['total_requests'] = metrics['num_images'] + metrics['num_scripts'] + metrics['num_stylesheets']
        
        # Check if scripts and styles are minified
        scripts = soup.find_all('script', src=True)
        stylesheets = soup.find_all('link', rel='stylesheet', href=True)
        
        num_minified_scripts = 0
        num_minified_stylesheets = 0
        
        for script in scripts:
            src = script['src']
            if not src.startswith('http'):
                src = urlparse(url)._replace(path=src).geturl()
            try:
                script_resp = requests.get(src, timeout=DEFAULT_TIMEOUT)
                script_resp.raise_for_status()
                if is_minified(script_resp.text):
                    num_minified_scripts +=1
            except requests.RequestException:
                continue
        
        for stylesheet in stylesheets:
            href = stylesheet['href']
            if not href.startswith('http'):
                href = urlparse(url)._replace(path=href).geturl()
            try:
                style_resp = requests.get(href, timeout=DEFAULT_TIMEOUT)
                style_resp.raise_for_status()
                if is_minified(style_resp.text):
                    num_minified_stylesheets +=1
            except requests.RequestException:
                continue
        
        metrics['minified_scripts'] = num_minified_scripts
        metrics['minified_stylesheets'] = num_minified_stylesheets
        
        return metrics
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving quality metrics: {e}")
        return None

def analyze_metrics(metrics):
    analysis = {}
    # Load Time Analysis
    load_time = metrics.get('load_time', 0)
    if load_time < 2:
        analysis['load_time'] = ('Good', 'Load time is excellent.')
    elif load_time < 5:
        analysis['load_time'] = ('Average', 'Load time is acceptable but could be improved.')
    else:
        analysis['load_time'] = ('Poor', 'Load time is slow and needs optimization.')
    
    # Page Size Analysis
    page_size = metrics.get('page_size', 0)
    if page_size < 500000:  # less than 500KB
        analysis['page_size'] = ('Good', 'Page size is small.')
    elif page_size < 2000000:  # less than 2MB
        analysis['page_size'] = ('Average', 'Page size is acceptable.')
    else:
        analysis['page_size'] = ('Poor', 'Page size is large and may affect load time.')
    
    # Total Requests Analysis
    total_requests = metrics.get('total_requests', 0)
    if total_requests < 50:
        analysis['total_requests'] = ('Good', 'Number of requests is low.')
    elif total_requests < 100:
        analysis['total_requests'] = ('Average', 'Number of requests is moderate.')
    else:
        analysis['total_requests'] = ('Poor', 'High number of requests may slow down the page.')
    
    # Compression Analysis
    compressed = metrics.get('compressed', False)
    if compressed:
        analysis['compressed'] = ('Good', 'Content is compressed.')
    else:
        analysis['compressed'] = ('Poor', 'Content is not compressed. Enable compression to improve load time.')
    
    # HTTPS Analysis
    https = metrics.get('https', False)
    if https:
        analysis['https'] = ('Good', 'Using HTTPS.')
    else:
        analysis['https'] = ('Poor', 'Not using HTTPS. It is recommended for security and SEO.')
    
    # Mobile Friendliness Analysis
    mobile_friendly = metrics.get('mobile_friendly', False)
    if mobile_friendly:
        analysis['mobile_friendly'] = ('Good', 'Page is mobile-friendly.')
    else:
        analysis['mobile_friendly'] = ('Poor', 'Page is not mobile-friendly.')
    
    # Minification Analysis
    num_scripts = metrics.get('num_scripts', 0)
    num_stylesheets = metrics.get('num_stylesheets', 0)
    minified_scripts = metrics.get('minified_scripts', 0)
    minified_stylesheets = metrics.get('minified_stylesheets', 0)
    
    if num_scripts > 0:
        script_minification_ratio = minified_scripts / num_scripts
        if script_minification_ratio > 0.8:
            analysis['scripts_minified'] = ('Good', 'Most scripts are minified.')
        else:
            analysis['scripts_minified'] = ('Poor', 'Consider minifying scripts to improve performance.')
    else:
        analysis['scripts_minified'] = ('N/A', 'No external scripts found.')
    
    if num_stylesheets > 0:
        style_minification_ratio = minified_stylesheets / num_stylesheets
        if style_minification_ratio > 0.8:
            analysis['styles_minified'] = ('Good', 'Most stylesheets are minified.')
        else:
            analysis['styles_minified'] = ('Poor', 'Consider minifying stylesheets to improve performance.')
    else:
        analysis['styles_minified'] = ('N/A', 'No external stylesheets found.')
    
    return analysis

def display_quality_metrics(metrics, analysis):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green")
    table.add_column("Analysis", style="yellow")
    
    table.add_row('Status Code', str(metrics.get('status_code', 'N/A')), '')
    table.add_row('Load Time (s)', f"{metrics.get('load_time', 0):.2f}", analysis.get('load_time', ('', ''))[1])
    table.add_row('Page Size (KB)', f"{metrics.get('page_size', 0)/1024:.2f}", analysis.get('page_size', ('', ''))[1])
    table.add_row('Total Requests', str(metrics.get('total_requests', 'N/A')), analysis.get('total_requests', ('', ''))[1])
    table.add_row('Compression Enabled', 'Yes' if metrics.get('compressed', False) else 'No', analysis.get('compressed', ('', ''))[1])
    table.add_row('HTTPS', 'Yes' if metrics.get('https', False) else 'No', analysis.get('https', ('', ''))[1])
    table.add_row('Mobile-Friendly', 'Yes' if metrics.get('mobile_friendly', False) else 'No', analysis.get('mobile_friendly', ('', ''))[1])
    table.add_row('Scripts Minified', f"{metrics.get('minified_scripts', 0)}/{metrics.get('num_scripts', 0)}", analysis.get('scripts_minified', ('', ''))[1])
    table.add_row('Stylesheets Minified', f"{metrics.get('minified_stylesheets', 0)}/{metrics.get('num_stylesheets', 0)}", analysis.get('styles_minified', ('', ''))[1])
    
    console.print(table)

def main(target):
    banner()
    console.print(Fore.WHITE + f"[*] Fetching quality metrics for: {target}")
    
    url = clean_url(target)
    metrics = get_quality_metrics(url)
    
    if metrics:
        analysis = analyze_metrics(metrics)
        display_quality_metrics(metrics, analysis)
    else:
        console.print(Fore.RED + "[!] No quality metrics found.")
    
    console.print(Fore.WHITE + "[*] Quality metrics retrieval completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a URL.")
        sys.exit(1)
