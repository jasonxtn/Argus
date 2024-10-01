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
          Argus - Advanced TLS Handshake Simulation
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        return parsed.hostname
    else:
        return domain.split('/')[0]

def simulate_tls_handshake(domain: str, ip: str = None, port: int = 443, tls_versions=None, ciphers=None):
    results = []
    target = ip if ip else domain

    if tls_versions is None:
        tls_versions = [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]

    for tls_version in tls_versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Removed deprecated options settings
            # context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.minimum_version = tls_version
            context.maximum_version = tls_version
            context.check_hostname = False  # Disable hostname checking
            context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

            if ciphers:
                context.set_ciphers(ciphers)

            with socket.create_connection((target, port), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert = tls_sock.getpeercert()
                    protocol_version = tls_sock.version()
                    cipher = tls_sock.cipher()
                    results.append({
                        "protocol_version": protocol_version,
                        "cipher": cipher,
                        "cert": cert,
                        "tls_version": tls_version.name
                    })
        except ssl.SSLError as e:
            console.print(Fore.YELLOW + f"[!] TLS {tls_version.name}: SSL error with {domain} ({ip if ip else 'IP not provided'}): {e}")
        except socket.timeout:
            console.print(Fore.RED + f"[!] TLS {tls_version.name}: Connection to {domain} timed out.")
        except Exception as e:
            console.print(Fore.RED + f"[!] TLS {tls_version.name}: Error performing TLS handshake with {domain} ({ip if ip else 'IP not provided'}): {e}")

    return results

def extract_cert_info(cert):
    subject = dict(x[0] for x in cert.get('subject', []))
    issuer = dict(x[0] for x in cert.get('issuer', []))
    valid_from = cert.get('notBefore')
    valid_to = cert.get('notAfter')
    serial_number = cert.get('serialNumber')
    san = cert.get('subjectAltName', [])
    return {
        "Subject": subject,
        "Issuer": issuer,
        "Valid From": valid_from,
        "Valid To": valid_to,
        "Serial Number": serial_number,
        "SAN": san
    }

def display_handshake_response(domain: str, ip: str, responses):
    if not responses:
        console.print(Fore.RED + f"[!] No successful handshake responses for {domain}.")
        return

    for response in responses:
        protocol_version = response.get('protocol_version', 'N/A')
        cipher_suite = response.get('cipher', ('N/A', 'N/A', 'N/A'))
        cert = response.get('cert', {})
        tls_version = response.get('tls_version', 'N/A')

        table = Table(title=f"TLS Handshake Details for {domain} ({ip or 'Resolved IP'}) - {tls_version}", show_header=False, box=box.SIMPLE)
        table.add_row("Protocol Version:", protocol_version)
        table.add_row("Cipher Suite:", cipher_suite[0])
        table.add_row("Cipher Protocol:", cipher_suite[1])
        table.add_row("Cipher Bits:", str(cipher_suite[2]))

        cert_info = extract_cert_info(cert)
        table.add_row("Certificate Subject:", str(cert_info.get("Subject", {})))
        table.add_row("Certificate Issuer:", str(cert_info.get("Issuer", {})))
        table.add_row("Valid From:", cert_info.get("Valid From", 'N/A'))
        table.add_row("Valid To:", cert_info.get("Valid To", 'N/A'))
        table.add_row("Serial Number:", cert_info.get("Serial Number", 'N/A'))
        table.add_row("Subject Alternative Names:", ', '.join(f"{typ}:{val}" for typ, val in cert_info.get("SAN", [])))
        console.print(table)

def parse_tls_versions(tls_versions_str):
    version_map = {
        'TLSv1': ssl.TLSVersion.TLSv1,
        'TLSv1.1': ssl.TLSVersion.TLSv1_1,
        'TLSv1.2': ssl.TLSVersion.TLSv1_2,
        'TLSv1.3': ssl.TLSVersion.TLSv1_3,
    }
    versions = []
    for v in tls_versions_str.split(','):
        v = v.strip()
        if v in version_map:
            versions.append(version_map[v])
        else:
            console.print(Fore.YELLOW + f"[!] Unsupported TLS version specified: {v}")
    return versions

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Argus - Advanced TLS Handshake Simulation')
    parser.add_argument('targets', nargs='+', help='Target domains or IPs (domain[:ip])')
    parser.add_argument('--port', type=int, default=443, help='Port to connect to (default: 443)')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--tls', type=str, help='Comma-separated TLS versions to test (e.g., TLSv1.2,TLSv1.3)')
    parser.add_argument('--ciphers', type=str, help='Custom cipher suites to use (OpenSSL format)')

    args = parser.parse_args()

    banner()

    if args.tls:
        tls_versions = parse_tls_versions(args.tls)
    else:
        tls_versions = [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]

    targets = []
    for target in args.targets:
        if ':' in target:
            domain_part, ip_part = target.split(':', 1)
            domain = clean_domain_input(domain_part)
            ip = ip_part
        else:
            domain = clean_domain_input(target)
            ip = None
        targets.append((domain, ip))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_target = {
            executor.submit(simulate_tls_handshake, domain, ip, args.port, tls_versions, args.ciphers): (domain, ip)
            for domain, ip in targets
        }
        for future in concurrent.futures.as_completed(future_to_target):
            domain, ip = future_to_target[future]
            responses = future.result()
            display_handshake_response(domain, ip, responses)

    console.print(Fore.CYAN + "[*] TLS handshake simulation completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
