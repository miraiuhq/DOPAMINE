import socket
import threading
import os
from colorama import Fore, Style

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))
        print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Port {port} open")
        s.close()
    except:
        pass

def run(target):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n  [{Fore.GREEN}>>>{Style.RESET_ALL}] Port scan on: {target}")
    print(f"  [{Fore.YELLOW}>>>{Style.RESET_ALL}] This manipulation can take time because it scans ALL ports.\n")

    threads = []

    for port in range(0, 65536):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        thread.join()

