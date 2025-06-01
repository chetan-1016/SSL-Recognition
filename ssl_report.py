import sys
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box
import time

console = Console()
DEFAULT_TIMEOUT = 10

def banner():
    console.print("\n[green]==============================================[/green]")
    console.print("[bold green]       SSL Lab Report Tool       [/bold green]")
    console.print("[green]==============================================\n[/green]")

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    parsed_url = urlparse(domain)
    return parsed_url.netloc if parsed_url.netloc else parsed_url.path

def fetch_ssl_report(domain, use_cache=True):
    try:
        base_url = "https://api.ssllabs.com/api/v3/analyze"
        params = {
            'host': domain,
            'fromCache': 'on' if use_cache else 'off',
            'all': 'done'
        }
        response = requests.get(base_url, params=params, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            status = data.get('status')
            if status == 'READY':
                return data
            elif status in ['DNS', 'IN_PROGRESS', 'RUNNING']:
                console.print(f"[*] Analysis in progress for {domain}. Waiting for results...")
                while status != 'READY':
                    time.sleep(5)
                    response = requests.get(base_url, params=params, timeout=DEFAULT_TIMEOUT)
                    data = response.json()
                    status = data.get('status')
                return data
            else:
                console.print(f"[red][!] Analysis failed for {domain}. Status: {status}[/red]")
                return None
        else:
            console.print(f"[red][!] Error fetching SSL report for {domain}: HTTP {response.status_code}[/red]")
            return None
    except requests.RequestException as e:
        console.print(f"[red][!] Error fetching SSL report for {domain}: {e}[/red]")
        return None

def display_ssl_report(domain, data):
    endpoints = data.get("endpoints", [])
    if not endpoints:
        console.print(f"[red][!] No endpoints found for {domain}.[/red]")
        return

    for endpoint in endpoints:
        ip_address = endpoint.get("ipAddress", "N/A")
        grade = endpoint.get("grade", "N/A")
        details = endpoint.get("details", {})

        protocols = details.get("protocols", [])
        suites_data = details.get("suites", {})

        # Fix for AttributeError: Handle different data formats
        if isinstance(suites_data, dict):
            cipher_suites = ', '.join([suite.get("name", "") for suite in suites_data.get("list", [])])
        elif isinstance(suites_data, list):
            cipher_suites = ', '.join([suite.get("name", "") for suite in suites_data])
        else:
            cipher_suites = 'N/A'

        server_signature = details.get("serverSignature", "N/A")
        ocsp_stapling = "Yes" if details.get("ocspStapling", False) else "No"
        hsts_status = details.get("hstsPolicy", {}).get("status", "N/A")
        vuln_beast = "Yes" if details.get("vulnBeast", False) else "No"
        poodle_tls = str(details.get("poodleTls", 0))
        heartbleed = "Yes" if details.get("heartbleed", False) else "No"
        supports_rc4 = "Yes" if details.get("supportsRc4", False) else "No"

        protocols_supported = ', '.join([f"{p.get('name', 'N/A')} {p.get('version', 'N/A')}" for p in protocols])

        table = Table(title=f"SSL Labs Report for {domain} [{ip_address}]", show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Field", style="cyan", justify="left")
        table.add_column("Details", style="green")

        table.add_row("Grade", grade)
        table.add_row("Protocols Supported", protocols_supported)
        table.add_row("Cipher Suites", cipher_suites)
        table.add_row("Server Signature", server_signature)
        table.add_row("OCSP Stapling", ocsp_stapling)
        table.add_row("HSTS Policy", hsts_status)
        table.add_row("Vulnerable to BEAST", vuln_beast)
        table.add_row("POODLE TLS", poodle_tls)
        table.add_row("Heartbleed Vulnerability", heartbleed)
        table.add_row("Supports RC4", supports_rc4)

        console.print(table)

def main():
    banner()
    console.print("[bold cyan]SSL Labs Report Tool[/bold cyan]")

    domain = input("Enter the domain to analyze: ").strip()
    if not domain:
        console.print("[bold red]Error:[/bold red] Domain name cannot be empty.")
        return

    domain = clean_domain_input(domain)
    console.print(f"[*] Fetching SSL Labs report for: {domain}")
    ssl_data = fetch_ssl_report(domain)

    if ssl_data:
        display_ssl_report(domain, ssl_data)
    else:
        console.print(f"[red][!] No SSL Labs data found for {domain}.[/red]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[red]\n[!] Process interrupted by user.[/red]")
        sys.exit(1)
