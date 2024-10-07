import sys
import os
import requests
import ssl
import urllib3
from rich.console import Console
import asyncio
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.events import HandshakeCompleted

# Suppress only the single InsecureRequestWarning from urllib3 needed.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to sys.path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import HEADERS, DEFAULT_TIMEOUT

console = Console()

def banner():
    console.print("""
[green]
=================================================
    Argus - HTTP/2 and HTTP/3 Support Checker
=================================================
[/green]
""")

def check_http2_support(target):
    console.print(f"[cyan][*] Checking for HTTP/2 support on {target}...[/cyan]")
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        adapter = requests.adapters.HTTPAdapter()
        session.mount('https://', adapter)
        response = session.get(target, timeout=DEFAULT_TIMEOUT, verify=False)
        if response.raw.version == 20:
            console.print("[green][+] HTTP/2 is supported.[/green]")
            return True
        else:
            console.print("[red][-] HTTP/2 is not supported.[/red]")
            return False
    except requests.exceptions.RequestException as e:
        console.print(f"[red][!] Error checking HTTP/2 support: {e}[/red]")
        return False

def check_http3_support(target):
    console.print(f"[cyan][*] Checking for HTTP/3 support on {target}...[/cyan]")
    async def http3_request():
        try:
            configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            configuration.verify_mode = ssl.CERT_NONE
            configuration.server_name = target.replace("https://", "").replace("http://", "").split('/')[0]
            async with connect(
                target.replace("https://", "").replace("http://", "").split('/')[0],
                443,
                configuration=configuration,
            ) as client:
                # Wait for handshake to complete
                await client.wait_connected()
                console.print("[green][+] HTTP/3 is supported.[/green]")
                return True
        except Exception as e:
            console.print(f"[red][-] HTTP/3 is not supported: {e}[/red]")
            return False

    try:
        asyncio.run(http3_request())
    except ImportError:
        console.print("[yellow][!] aioquic library is not installed. Skipping HTTP/3 check.[/yellow]")
        console.print("[cyan][*] Install aioquic using 'pip install aioquic' to enable HTTP/3 checking.[/cyan]")
    except Exception as e:
        console.print(f"[red][!] Error checking HTTP/3 support: {e}[/red]")

def main(target):
    banner()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    check_http2_support(target)
    check_http3_support(target)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            main(target)
            sys.exit(0)
        except KeyboardInterrupt:
            console.print("\n[red][!] Script interrupted by user.[/red]")
            sys.exit(0)
        except Exception as e:
            console.print(f"[red][!] An unexpected error occurred: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
