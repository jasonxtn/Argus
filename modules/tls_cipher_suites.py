import sys
import ssl
import socket
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import Fore, init
import concurrent.futures

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 5

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - Advanced TLS Cipher Analysis
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        return parsed.hostname
    else:
        return domain.split('/')[0]

def get_all_ciphers():
    context = ssl.create_default_context()
    context.set_ciphers('ALL:@SECLEVEL=0')
    ciphers = context.get_ciphers()
    return list({cipher.get('name') for cipher in ciphers if cipher.get('name')})

def get_available_tls_versions():
    tls_versions = []
    if hasattr(ssl, 'TLSVersion'):
        deprecated_versions = {
            ssl.TLSVersion.SSLv3,
            ssl.TLSVersion.TLSv1,
            ssl.TLSVersion.TLSv1_1,
        }
        tls_versions = [version for version in ssl.TLSVersion if version not in deprecated_versions]
    else:
        versions = [
            ssl.PROTOCOL_TLSv1_2,
            getattr(ssl, 'PROTOCOL_TLSv1_3', None)
        ]
        tls_versions = [v for v in versions if v is not None]
    return tls_versions

def test_cipher(domain: str, port: int, cipher: str, tls_version):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_ciphers(cipher)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if hasattr(context, 'minimum_version'):
            context.minimum_version = tls_version
            context.maximum_version = tls_version
        else:
            # For older Python versions
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            if tls_version == ssl.PROTOCOL_TLSv1_2:
                context.options |= getattr(ssl, 'OP_NO_TLSv1_3', 0)
            elif getattr(ssl, 'PROTOCOL_TLSv1_3', None) and tls_version == ssl.PROTOCOL_TLSv1_3:
                context.options &= ~getattr(ssl, 'OP_NO_TLSv1_3', 0)
            else:
                return None  # Unsupported version

        with socket.create_connection((domain, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol = ssock.version()
                return cipher, protocol
    except ssl.SSLError:
        return None
    except Exception:
        return None

def get_supported_ciphers(domain: str, port: int = 443):
    ciphers = get_all_ciphers()
    supported_ciphers = []
    tls_versions = get_available_tls_versions()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_cipher = {
            executor.submit(test_cipher, domain, port, cipher, tls_version): (cipher, tls_version)
            for tls_version in tls_versions for cipher in ciphers
        }
        for future in concurrent.futures.as_completed(future_to_cipher):
            result = future.result()
            if result:
                cipher, protocol = result
                supported_ciphers.append((cipher, protocol))
    return supported_ciphers

def analyze_ciphers(supported_ciphers: list):
    weak_ciphers = []
    weak_indicators = [
        'RC4', 'DES', 'MD5', 'NULL', 'EXP', 'RC2', 'IDEA',
        'SEED', 'CAMELLIA', 'ANON', 'CBC', 'SHA1', '3DES'
    ]
    for cipher, protocol in supported_ciphers:
        if any(weak in cipher.upper() for weak in weak_indicators):
            weak_ciphers.append((cipher, protocol))
    return weak_ciphers

def display_supported_ciphers(domain: str, supported_ciphers: list):
    table = Table(
        title=f"Supported Cipher Suites for {domain}",
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED
    )
    table.add_column("Cipher Suite", style="cyan")
    table.add_column("Protocol Version", style="green")
    for cipher, protocol in supported_ciphers:
        table.add_row(cipher, protocol)
    console.print(table)

    weak_ciphers = analyze_ciphers(supported_ciphers)
    if weak_ciphers:
        console.print(Fore.YELLOW + "[*] Weak or insecure cipher suites detected:")
        weak_table = Table(
            title="Weak Cipher Suites",
            show_header=True,
            header_style="bold red",
            box=box.ROUNDED
        )
        weak_table.add_column("Cipher Suite", style="cyan")
        weak_table.add_column("Protocol Version", style="green")
        for cipher, protocol in weak_ciphers:
            weak_table.add_row(cipher, protocol)
        console.print(weak_table)
    else:
        console.print(Fore.GREEN + "[+] No weak cipher suites detected.")

def main(targets):
    banner()
    for target in targets:
        domain = clean_domain_input(target)
        if not domain:
            console.print(Fore.RED + f"[!] Invalid domain provided: {target}")
            continue
        console.print(Fore.WHITE + f"[*] Fetching TLS cipher suites for: {domain}")
        supported_ciphers = get_supported_ciphers(domain)
        if supported_ciphers:
            display_supported_ciphers(domain, supported_ciphers)
        else:
            console.print(Fore.RED + f"[!] No TLS cipher suites found or unable to connect to {domain}.")
    console.print(Fore.CYAN + "[*] TLS cipher suites analysis completed.")

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            targets = sys.argv[1:]
            main(targets)
        else:
            console.print(Fore.RED + "[!] No domain provided. Please pass one or more domains.")
            sys.exit(1)
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
