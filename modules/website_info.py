import socket
import requests
import os
from colorama import Fore, Style

def run(domain):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n  [{Fore.GREEN}>>>{Style.RESET_ALL}] Website information for: {domain}\n")

    try:
        ip = socket.gethostbyname(domain)
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] IP Address: {ip}")
    except:
        print(f"  [{Fore.RED}-{Style.RESET_ALL}] Could not resolve domain")
        return
    
    try:
        rev = socket.gethostbyaddr(ip)
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Reverse DNS: {rev[0]}")
    except:
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] No reverse DNS found")

    try:
        r = requests.get(f"http://{domain}", timeout=3)
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] HTTP Headers:")
        for k, v in r.headers.items():
            print(f"      -  {k}: {v}")
    except:
        print(f"  [{Fore.RED}-{Style.RESET_ALL}] Could not fetch HTTP headers")
