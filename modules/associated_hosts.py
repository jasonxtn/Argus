import os
import sys
import requests
from colorama import Fore, init, Style

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DEFAULT_TIMEOUT, API_KEYS  
from utils.util import resolve_to_ip  

init(autoreset=True)

def banner():
    print(Fore.WHITE + """
    =============================================
        Argus - Associated Hosts Detection
    =============================================
    """ + Style.RESET_ALL)

def get_associated_hosts_shodan(ip):
    api_key = API_KEYS.get("SHODAN_API_KEY")  
    if not api_key:
        print(Fore.WHITE + "[!] Shodan API key not configured, using HackerTarget instead..." + Style.RESET_ALL)
        return "NO_API"

    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            return data.get('hostnames', [])
        else:
            print(Fore.RED + f"[!] Shodan API error: {response.status_code}" + Style.RESET_ALL)
            return None
    except requests.RequestException as e:
        print(Fore.WHITE + f"[!] Error connecting to Shodan: {e}" + Style.RESET_ALL)
        return None

def get_associated_hosts_hackertarget(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200 and "error" not in response.text.lower():
            hosts = response.text.strip().split("\n")
            return hosts
        else:
            print(Fore.RED + f"[!] Error from HackerTarget API: {response.text.strip()}" + Style.RESET_ALL)
            return None
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error connecting to HackerTarget: {e}" + Style.RESET_ALL)
        return None

def display_associated_hosts(hosts):
    if hosts:
        print(Fore.WHITE + "\n[*] Associated Hosts:" + Style.RESET_ALL)
        print(Fore.WHITE + "=" * 60 + Style.RESET_ALL)
        for host in hosts:
            print(Fore.WHITE + f"{host}" + Style.RESET_ALL)
        print(Fore.WHITE + "=" * 60 + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No associated hosts found." + Style.RESET_ALL)

def main(target):
    banner()
    print(Fore.CYAN + f"[*] Detecting associated hosts for: {target}" + Style.RESET_ALL)

    ip = resolve_to_ip(target)
    if not ip:
        print(Fore.WHITE + "[!] Could not resolve target to an IP address." + Style.RESET_ALL)
        sys.exit(1)

    associated_hosts = get_associated_hosts_shodan(ip)

    if associated_hosts == "NO_API" or not associated_hosts:
        print(Fore.YELLOW + "[!] No results from Shodan, falling back to HackerTarget..." + Style.RESET_ALL)
        associated_hosts = get_associated_hosts_hackertarget(ip)

    display_associated_hosts(associated_hosts)

    print(Fore.WHITE + "[*] Associated hosts detection completed." + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print(Fore.WHITE + "[!] No target provided. Please pass a domain, URL, or IP address." + Style.RESET_ALL)
        sys.exit(1)
