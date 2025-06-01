import socket
import ssl
import hashlib
from datetime import datetime
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

init(autoreset=True)
console = Console()
def banner():
    console.print(Fore.GREEN + """
    =============================================
        SSL Inspector - Certificate Analyzer
    =============================================
    """)
    
def get_ssl_certificate(domain):
    """Retrieve the SSL certificate of a given domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)  
                return cert, cert_der
    except (ssl.SSLError, socket.error, socket.timeout) as e:
        console.print(Fore.RED + f"[!] SSL/Socket error: {e}")
        return None, None

def get_fingerprint(cert_der):
    """Generate SHA-256 fingerprint of the certificate."""
    if cert_der:
        sha256_fp = hashlib.sha256(cert_der).hexdigest()
        return ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))
    return "N/A"

def analyze_certificate(cert, cert_der):
    """Analyze the SSL certificate details."""
    if not cert:
        return None

    def format_cert_field(field):
        return ", ".join(f"{sub_entry[0]}: {sub_entry[1]}" for entry in cert.get(field, []) for sub_entry in entry)

    analysis = {
        "Issuer": format_cert_field("issuer"),
        "Subject": format_cert_field("subject"),
        "Valid From": cert.get("notBefore", "N/A"),
        "Valid Until": cert.get("notAfter", "N/A"),
        "Serial Number": cert.get("serialNumber", "N/A"),
        "Version": cert.get("version", "N/A"),
        "Signature Algorithm": cert.get("signatureAlgorithm", "N/A"),
        "Fingerprint (SHA-256)": get_fingerprint(cert_der),
    }

    try:
        analysis["Valid From"] = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        analysis["Valid Until"] = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        analysis["Days Until Expiry"] = (analysis["Valid Until"] - datetime.utcnow()).days
    except:
        analysis["Days Until Expiry"] = "N/A"

    return analysis

def display_certificate_info(cert_analysis):
    """Display certificate details in a table format."""
    if not cert_analysis:
        console.print(Fore.RED + "[!] No certificate data available.")
        return

    table = Table(title="SSL Certificate Details", show_header=True, header_style="bold magenta")
    table.add_column("Attribute", style="cyan", justify="left")
    table.add_column("Details", style="green", justify="left")
