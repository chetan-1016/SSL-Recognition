import os
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize Colorama
init(autoreset=True)
os.system("clear")

# Banner
banner = f"""
{Fore.BLUE}┌{'─'*68}┐
│{Fore.GREEN}{Style.BRIGHT}          🚀  SSL CERTIFICATE ANALYZER  🚀                      {Fore.BLUE}
├{'─'*68}┤
│{Fore.YELLOW}                        Author   : G16                                             {Fore.BLUE}
├{'─'*68}┤
│{Fore.CYAN}{Style.BRIGHT}   DESCRIPTION:{Style.RESET_ALL}                                                {Fore.BLUE}
│{Fore.MAGENTA}   This SSL Certificate Analysis Tool helps you inspect and      {Fore.MAGENTA}   |
│   understand a website's security by analyzing the SSL             │
│   certificate chain, checking expiry dates, generating             │
│   detailed certificate reports, and detecting SSL pinning.         │
│   It ensures each certificate in the chain is valid, alerts        │
│   you to upcoming expirations, and explains key details like       │
│   issuer and encryption. SSL pinning detection adds insight        │
│   into protection against man-in-the-middle attacks. Designed      │
│   for beginners, this tool makes SSL security simple and easy      │
│   to understand.                                                   │
└{'─'*68}┘
"""
print(banner)

# Menu options with mapping
MODULES = {
    "1": ("modules/ssl_chain.py", "SSL Certificate Chain Analysis"),
    "2": ("modules/ssl_expiry.py", "SSL Certificate Expiry Check"),
    "3": ("modules/ssl_report.py", "SSL Certificate Report"),
    "4": ("modules/ssl_pinning.py", "SSL Pinning Detection"),
    "0": ("exit", "Exit Tool")
}

def display_menu():
    print(f"\n{Fore.BLUE}{Style.BRIGHT}Available Modules:\n")
    table_data = [(key, desc) for key, (_, desc) in MODULES.items()]
    print(Fore.CYAN + tabulate(table_data, headers=["Option", "Description"], tablefmt="fancy_grid"))

def main_menu():
    while True:
        display_menu()
        choice = input(f"\n{Fore.YELLOW}{Style.BRIGHT}Enter your choice: {Fore.RESET}").strip()

        if choice in MODULES:
            script, desc = MODULES[choice]
            if script == "exit":
                print(f"\n{Fore.RED}{Style.BRIGHT}Exiting...{Style.RESET_ALL}")
                break
            print(f"\n{Fore.CYAN}Running: {desc}\n")
            os.system(f"python {script}")
            input(f"\n{Fore.GREEN}Press Enter to return to menu...")
        else:
            print(f"\n{Fore.RED}Invalid choice! Please enter a valid option.")

if __name__ == "__main__":
    main_menu()