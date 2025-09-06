import sys, os, time
from modules import port_scanner, auto_scan, website_info
from utils.banner import show_banner
from colorama import init, Fore, Style

init(autoreset=True)

def menu():
    show_banner()
    print(f"""    [{Fore.CYAN}1{Style.RESET_ALL}] Port Scanner
    [{Fore.CYAN}2{Style.RESET_ALL}] Vulnerability researcher
    [{Fore.CYAN}3{Style.RESET_ALL}] Website Info
    [{Fore.CYAN}0{Style.RESET_ALL}] Exit
""")

def main():
    while True:
        menu()
        choice = input(f"  [{Fore.CYAN}~{Style.RESET_ALL}] Choose an option: ")

        if choice == "1":
            target = input(f"  [{Fore.CYAN}~{Style.RESET_ALL}] Target (IP or domain): ").strip()
            port_scanner.run(target)
        elif choice == "2":
            url = input(f"  [{Fore.CYAN}~{Style.RESET_ALL}] URL to scan: ").strip()
            if not url.startswith("http"):
                url = "http://" + url
            auto_scan.run(url)
            input(f"\n  [{Fore.MAGENTA}>{Style.RESET_ALL}] Press Enter to return to the menu...")
            menu()
        elif choice == "3":
            domain = input(f"  [{Fore.MAGENTA}>{Style.RESET_ALL}] Target domain: ").strip()
            website_info.run(domain)
            input(f"\n  [{Fore.MAGENTA}>{Style.RESET_ALL}] Press Enter to return to menu...")
            menu()
        elif choice == "0":
            os.system('cls' if os.name == 'nt' else 'clear')
            sys.exit("\n\n\n\n              Bye! :3")
        else:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n\n\n\n              Invalid option! :(")
            time.sleep(1)
            menu()

if __name__ == "__main__":
    main()
