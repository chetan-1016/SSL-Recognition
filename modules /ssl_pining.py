import sys
import ssl
import socket
import concurrent.futures
import hashlib
import json
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import box
import validators
import requests

console = Console()
DEFAULT_TIMEOUT = 10

def banner():
    console.print("[bold cyan]==========================================[/]")
    console.print("[bold green]        SSL PINNING CHECK TOOL       [/]")
    console.print("[bold cyan]==========================================[/]\n")

def clean_domain(domain: str) -> str:
    """ Sanitize and extract a valid domain name from input """
    domain = domain.strip()
    parsed_url = urlparse(domain)
    extracted_domain = parsed_url.netloc or parsed_url.path
    return extracted_domain if validators.domain(extracted_domain) else None

def get_ssl_certificate_fingerprint(domain: str):
    """ Extract SSL certificate fingerprint using SHA-256 """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(cert).hexdigest().upper()
                return fingerprint
    except Exception as e:
        return {"domain": domain, "error": f"SSL Error: {str(e)}"}

def check_hsts(domain: str):
    """ Check if HSTS (Strict Transport Security) is enabled """
    try:
        response = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT, verify=True)
        hsts_enabled = "Strict-Transport-Security" in response.headers
        return hsts_enabled
    except requests.RequestException:
        return None

def process_domain(domain):
    """ Validate, process, and extract SSL certificate fingerprint """
    clean_domain_name = clean_domain(domain)
    if not clean_domain_name:
        return {"domain": domain, "error": "Invalid domain format"}

    console.print(f"[white][*] Checking SSL certificate for: {clean_domain_name}[/]")

    fingerprint = get_ssl_certificate_fingerprint(clean_domain_name)
    if isinstance(fingerprint, dict):  
        return fingerprint

    hsts_status = check_hsts(clean_domain_name)

    return {
        "domain": clean_domain_name,
        "ssl_pinning": True,  
        "fingerprint": fingerprint,
        "hsts": hsts_status
    }

def display_results(results):
    """ Display results in a formatted table """
    table = Table(title="SSL Pinning Check Results", show_header=True, header_style="bold cyan", box=box.MINIMAL)
    table.add_column("Domain", style="cyan", justify="left")
    table.add_column("SSL Pinning (SHA-256 Fingerprint)", style="green", justify="left")
    table.add_column("HSTS", style="yellow", justify="center")

    for result in results:
        if "error" in result:
            table.add_row(result["domain"], f"[red]{result['error']}[/]", "[red]N/A[/]")
        else:
            hsts_status = "✅ Enabled" if result["hsts"] else "❌ Not Found"
            table.add_row(result["domain"], f"[blue]{result['fingerprint']}[/]", hsts_status)

    console.print(table)

def main():
    banner()

    # Ask for domain input
    domain_input = input("Enter the domain(s) (comma-separated if multiple): ").strip()
    domains = [d.strip() for d in domain_input.split(",") if d.strip()]

    if not domains:
        console.print("[red][!] No valid domains entered. Exiting...[/]")
        sys.exit(1)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        with Progress() as progress:
            task = progress.add_task("[cyan]Checking SSL Certificates...", total=len(domains))
            futures = {executor.submit(process_domain, domain): domain for domain in domains}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                progress.update(task, advance=1)

    display_results(results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[red]\n[!] Process interrupted by user.[/]")
        sys.exit(1)
