from colorama import init, Fore, Style
import os

init(autoreset=True)

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""\n  ___   ___  ___  _   __  __ ___ _  _ ___ \n |   \ / _ \| _ \/_\ |  \/  |_ _| \| | __|\n | |) | (_) |  _/ _ \| |\/| || || .` | _| \n |___/ \___/|_|/_/ \_\_|  |_|___|_|\_|___|                                    \n                                                 \n             developed by {Fore.CYAN}mirai{Style.RESET_ALL}\n    """)
