import os
import sys
import requests
from colorama import Fore, init
from random import choice
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url, ensure_directory_exists  
from config.settings import RESULTS_DIR, DEFAULT_TIMEOUT  


init(autoreset=True)


output_lock = Lock()


user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
]

custom_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive'
}

def banner():
    """Displays the banner."""
    print(Fore.GREEN + """
    =============================================
          Argus - Directory Finder
    =============================================
    """)

def status(message):
    with output_lock:
        print(Fore.WHITE + f"[*] {message}")

def success(message):
    with output_lock:
        print(Fore.GREEN + f"[+] {message}")

def error(message):
    with output_lock:
        print(Fore.RED + f"[!] {message}")

class ContentDiscovery:
    def __init__(self, target):
        banner()
        self.base_url, self.paths = self.prepare_target(target)
        self.total_attempts = len(self.paths)
        self.attempt_number = 0
        self.found_directories = []
        self.queue = Queue()
        for path in self.paths:
            self.queue.put(self.clean_path(path))
        self.run()

    def clean_path(self, path):
        return path.lstrip('/')

    def prepare_target(self, target):
        base_url = clean_url(target)
        status(f"Target base URL set to: {base_url}")

        wordlist_file = os.path.join('wordlists', "directory_wordlists.txt")
        status(f"Loading paths from {wordlist_file}...")
        if not os.path.isfile(wordlist_file):
            error(f"Wordlist file not found: {wordlist_file}")
            sys.exit(1)
        with open(wordlist_file, 'r', encoding='utf-8') as f:
            paths = [line.strip() for line in f if line.strip()]
        if not paths:
            error("No paths found in the wordlist.")
            sys.exit(1)
        success(f"{len(paths)} paths loaded from the wordlist.")
        return base_url, paths

    def run(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_path, self.queue.get()): self.queue.get() for _ in range(self.queue.qsize())}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    future.result()
                except Exception as e:
                    error(f"Error processing path {path}: {e}")

        if self.found_directories:
            success("Directories found:")
            for directory in self.found_directories:
                print(Fore.WHITE + directory)
            ensure_directory_exists(RESULTS_DIR)
            with open(os.path.join(RESULTS_DIR, 'directory_finder.txt'), 'w') as writer:
                writer.write("\n".join(self.found_directories))
            success("Results saved in 'Results/directory_finder.txt'")
        else:
            status("No directories found.")

    def check_path(self, path):
        full_url = f"{self.base_url}/{path}"
        try:
            headers = custom_headers.copy()
            headers['User-Agent'] = choice(user_agents)
            response = requests.get(full_url, headers=headers, timeout=DEFAULT_TIMEOUT)

            self.attempt_number += 1
            progress = f"{(self.attempt_number / self.total_attempts) * 100:.2f}%"

            if response.status_code in [200, 301, 302, 403]:
                self.found_directories.append(full_url)
                success_msg = f"\n[{self.attempt_number}/{self.total_attempts}] Tested - {full_url} [{progress}]\n"
                print(Fore.GREEN + success_msg)
            else:
                with output_lock:
                    sys.stdout.write(f'\r[{self.attempt_number}/{self.total_attempts}] Tested - Current: {full_url} [{progress}]')
                    sys.stdout.flush()

        except requests.exceptions.RequestException as e:
            error(f"Failed to connect to {full_url}: {str(e)}")

def main(target):
    ContentDiscovery(target)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
