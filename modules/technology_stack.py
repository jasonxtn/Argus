import os
import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
import logging

# Check for required modules
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

# Initialize Colorama and Rich Console
init(autoreset=True)
console = Console()

# Configure logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, 'technology_stack_detection.log')
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to handle the banner
def banner():
    print(Fore.WHITE + """
=============================================
        Argus - Technology Stack Detection
=============================================
""")

# First approach: Parse HTML content
def detect_by_html(url):
    tech_stack = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        # Detect technologies based on tags and attributes
        if soup.find('script', src=lambda x: x and 'wp-content' in x):
            tech_stack.append({'technology': 'WordPress', 'categories': ['CMS']})

        if soup.find('meta', attrs={'name': 'generator', 'content': lambda x: x and 'Joomla' in x}):
            tech_stack.append({'technology': 'Joomla', 'categories': ['CMS']})

        if soup.find('link', href=lambda x: x and 'sites/all/themes' in x):
            tech_stack.append({'technology': 'Drupal', 'categories': ['CMS']})

        if soup.find('script', src=lambda x: x and 'jquery' in x):
            tech_stack.append({'technology': 'jQuery', 'categories': ['JavaScript Library']})

        if soup.find('script', src=lambda x: x and 'react' in x):
            tech_stack.append({'technology': 'React', 'categories': ['JavaScript Framework']})

        if soup.find('script', src=lambda x: x and 'angular' in x):
            tech_stack.append({'technology': 'AngularJS', 'categories': ['JavaScript Framework']})

        if soup.find('script', src=lambda x: x and 'vue' in x):
            tech_stack.append({'technology': 'Vue.js', 'categories': ['JavaScript Framework']})

        if soup.find('link', href=lambda x: x and 'bootstrap' in x):
            tech_stack.append({'technology': 'Bootstrap', 'categories': ['CSS Framework']})

        # Check meta generator tags
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            content = generator.get('content')
            if 'WordPress' in content:
                tech_stack.append({'technology': 'WordPress', 'categories': ['CMS']})
            elif 'Joomla' in content:
                tech_stack.append({'technology': 'Joomla', 'categories': ['CMS']})
            elif 'Drupal' in content:
                tech_stack.append({'technology': 'Drupal', 'categories': ['CMS']})

        # Add more detection logic as needed

    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error retrieving HTML content: {e}")
        logging.error(f"Error retrieving HTML content: {e}")
    return tech_stack

# Second approach: Analyze HTTP headers
def detect_by_headers(url):
    tech_stack = []
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        response.raise_for_status()

        headers = response.headers

        server = headers.get('Server', '')
        x_powered_by = headers.get('X-Powered-By', '')

        # Detect technologies based on Server header
        if 'Apache' in server:
            tech_stack.append({'technology': 'Apache', 'categories': ['Web Server']})
        if 'nginx' in server:
            tech_stack.append({'technology': 'Nginx', 'categories': ['Web Server']})
        if 'IIS' in server:
            tech_stack.append({'technology': 'Microsoft IIS', 'categories': ['Web Server']})

        # Detect technologies based on X-Powered-By header
        if 'PHP' in x_powered_by:
            tech_stack.append({'technology': 'PHP', 'categories': ['Programming Language']})
        if 'ASP.NET' in x_powered_by:
            tech_stack.append({'technology': 'ASP.NET', 'categories': ['Web Framework']})
        if 'Express' in x_powered_by:
            tech_stack.append({'technology': 'Express', 'categories': ['Web Framework']})

        # Add more detection logic as needed

    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error retrieving HTTP headers: {e}")
        logging.error(f"Error retrieving HTTP headers: {e}")
    return tech_stack

# Third approach: Check for specific files or endpoints
def detect_by_files(url):
    tech_stack = []
    try:
        # List of tuples (path, technology, category)
        checks = [
            ('/wp-login.php', 'WordPress', 'CMS'),
            ('/administrator/', 'Joomla', 'CMS'),
            ('/user/login', 'Drupal', 'CMS'),
            ('/scripts/setup.php', 'phpMyAdmin', 'Database Administration'),
            ('/favicon.ico', 'Favicon', 'Miscellaneous'),
            ('/robots.txt', 'Robots.txt', 'Miscellaneous'),
        ]

        for path, technology, category in checks:
            full_url = url.rstrip('/') + path
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                tech_stack.append({'technology': technology, 'categories': [category]})

    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error checking specific files: {e}")
        logging.error(f"Error checking specific files: {e}")
    return tech_stack

def display_tech_stack(tech_stack):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Technology", style="cyan", justify="left")
    table.add_column("Categories", style="green")

    # Remove duplicates
    seen = set()
    unique_tech = []
    for tech in tech_stack:
        tech_id = (tech['technology'], ','.join(tech['categories']))
        if tech_id not in seen:
            seen.add(tech_id)
            unique_tech.append(tech)

    for tech in unique_tech:
        table.add_row(tech.get('technology', 'Unknown'), ', '.join(tech.get('categories', ['N/A'])))

    console.print(table)

def save_results(tech_stack, target):
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Results')
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    filename = os.path.join(results_dir, f"technology_stack_{target.replace('://', '_').replace('/', '_')}.txt")
    try:
        with open(filename, 'w') as f:
            for tech in tech_stack:
                f.write(f"Technology: {tech.get('technology', 'Unknown')}\n")
                f.write(f"Categories: {', '.join(tech.get('categories', ['N/A']))}\n")
                f.write('---\n')
        print(Fore.GREEN + f"[+] Results saved to {filename}")
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving results: {e}")
        logging.error(f"Error saving results: {e}")

def main(target):
    banner()
    print(Fore.WHITE + f"[*] Detecting technology stack for: {target}")
    logging.info(f"Started technology stack detection for: {target}")

    # Ensure the URL has scheme
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    tech_stack = []

    # First approach
    print(Fore.CYAN + "[*] Analyzing HTML content...")
    tech_stack += detect_by_html(target)

    # Second approach
    print(Fore.CYAN + "[*] Analyzing HTTP headers...")
    tech_stack += detect_by_headers(target)

    # Third approach
    print(Fore.CYAN + "[*] Checking for specific files and endpoints...")
    tech_stack += detect_by_files(target)

    if tech_stack:
        print(Fore.GREEN + "[+] Technologies detected:")
        display_tech_stack(tech_stack)
        save_results(tech_stack, target)
    else:
        console.print(Fore.RED + "[!] No technology stack data found.")
        logging.info("No technology stack data found.")

    print(Fore.CYAN + "[*] Technology stack detection completed.")
    logging.info("Technology stack detection completed.")

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
