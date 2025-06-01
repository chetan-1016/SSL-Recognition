import ssl
import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table

def fetch_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                days_left = (expiry_date - datetime.utcnow()).days
                return domain, expiry_date, days_left, cert
    except Exception as e:
        return domain, None, None, str(e)

def display_ssl_info(domain, expiry_date, days_left, cert):
    console = Console()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("SSL Expiry Details", style="cyan", justify="left")
    table.add_column("Value", style="green")
    table.add_row("Domain", domain)
    table.add_row("Expiry Date", expiry_date.strftime("%Y-%m-%d %H:%M:%S") if expiry_date else "N/A")
    table.add_row("Days Left", str(days_left) if days_left is not None else "N/A")
    console.print(table)

    if isinstance(cert, dict):
        analysis_table = Table(show_header=True, header_style="bold magenta")
        analysis_table.add_column("Attribute", style="cyan", justify="left")
        analysis_table.add_column("Details", style="green", justify="left")
        subject = ", ".join(f"{name}={value}" for sub in cert.get("subject", []) for (name, value) in sub)
        issuer = ", ".join(f"{name}={value}" for sub in cert.get("issuer", []) for (name, value) in sub)
        valid_from = cert.get("notBefore", "N/A")
        valid_until = cert.get("notAfter", "N/A")
        serial_number = cert.get("serialNumber", "N/A")
        version = cert.get("version", "N/A")
        signature_algorithm = cert.get("signatureAlgorithm", "N/A")

        analysis_table.add_row("Subject", subject)
        analysis_table.add_row("Issuer", issuer)
        analysis_table.add_row("Valid From", valid_from)
        analysis_table.add_row("Valid Until", valid_until)
        analysis_table.add_row("Validity Period (Days)", str((expiry_date - datetime.strptime(valid_from, '%b %d %H:%M:%S %Y GMT')).days) if expiry_date else "N/A")
        analysis_table.add_row("Days Until Expiry", str(days_left) if days_left is not None else "N/A")
        analysis_table.add_row("Serial Number", serial_number)
        analysis_table.add_row("Version", str(version))
        analysis_table.add_row("Signature Algorithm", signature_algorithm)

        console.print(analysis_table)

def main():
    console = Console()
    console.print("[bold cyan]SSL Expiry Check Tool[/bold cyan]")

    domain = input("Enter the domain to check SSL expiry: ").strip()
    if not domain:
        console.print("[bold red]Error:[/bold red] Domain name cannot be empty.")
        return

    domain, expiry_date, days_left, cert = fetch_ssl_info(domain)
    display_ssl_info(domain, expiry_date, days_left, cert)

if __name__ == "__main__":
    main()
