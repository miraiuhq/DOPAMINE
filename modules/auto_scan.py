import requests
import re
import os
from colorama import init, Fore, Style

init(autoreset=True)

SQLI = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
XSS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
CMDI = ["; id", "&& whoami", "| whoami"]
SSTI = ["{{7*7}}", "${7*7}", "#{7*7}"]
PATH_TRAVERSAL = ["../../etc/passwd", "../../../etc/passwd"]
REDIRECTS = ["?next=https://evil.com", "?redirect=https://evil.com"]

SENSITIVE_FILES = [
    ".env", ".git/config", "config.php", "db.sql", "phpinfo.php",
    "backup.zip", "index.php~", "config.old"
]

COMMON_DIRS = ["admin", "login", "uploads", "backup", "test", "phpmyadmin"]

CMS_SIGNATURES = {
    "WordPress": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
    "Joomla": ["/administrator/", "Joomla!"],
    "Drupal": ["/user/login", "drupal.js"],
    "Laravel": [".env", "X-Powered-By: PHP/"]
}

CVE_DB = {
    "WordPress": {
        "5.0": ["CVE-2019-8942 - Arbitrary file delete"],
        "5.4": ["CVE-2020-4047 - XSS in customizer"],
        "5.7": ["CVE-2021-29447 - XXE in media library"]
    },
    "Joomla": {
        "3.7": ["CVE-2017-8917 - SQL Injection"],
        "3.9": ["CVE-2019-10945 - XSS"],
    },
    "Drupal": {
        "7": ["CVE-2018-7600 - Drupalgeddon2 (RCE)"],
        "8.3": ["CVE-2017-6920 - Access bypass"],
    },
    "Laravel": {
        "5.7": ["CVE-2019-9081 - Remote Code Execution"],
        "8.4": ["CVE-2021-3129 - Debug mode RCE"],
    }
}

def test_sqli(url):
    for p in SQLI:
        try:
            r = requests.get(url + p, timeout=5)
            if any(err in r.text.lower() for err in ["sql", "mysql", "syntax", "error"]):
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] SQLi possible: {url + p}")
        except: pass

def test_xss(url):
    for p in XSS:
        try:
            r = requests.get(url, params={"q": p}, timeout=5)
            if p in r.text:
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] XSS detected: {url}?q={p}")
        except: pass

def test_cmdi(url):
    for p in CMDI:
        try:
            r = requests.get(url, params={"cmd": p}, timeout=5)
            if "uid=" in r.text or "root" in r.text:
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Command Injection: {url}?cmd={p}")
        except: pass

def test_ssti(url):
    for p in SSTI:
        try:
            r = requests.get(url, params={"name": p}, timeout=5)
            if "49" in r.text or "34359738368" in r.text:
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] SSTI detected: {url}?name={p}")
        except: pass

def test_traversal(url):
    for p in PATH_TRAVERSAL:
        try:
            r = requests.get(url, params={"file": p}, timeout=5)
            if "root:" in r.text or "[extensions]" in r.text:
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Path Traversal: {url}?file={p}")
        except: pass

def test_redirect(url):
    for p in REDIRECTS:
        try:
            r = requests.get(url + p, allow_redirects=False, timeout=5)
            if r.status_code in [301, 302] and "evil.com" in r.headers.get("Location", ""):
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Open Redirect: {url + p}")
        except: pass

def check_sensitive_files(base_url):
    if not base_url.endswith("/"): base_url += "/"
    for f in SENSITIVE_FILES:
        try:
            r = requests.get(base_url + f, timeout=5)
            if r.status_code == 200 and len(r.text) > 20:
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Sensitive file found: {base_url + f}")
        except: pass

def brute_force_dirs(base_url):
    if not base_url.endswith("/"): base_url += "/"
    for d in COMMON_DIRS:
        try:
            r = requests.get(base_url + d, timeout=5)
            if r.status_code == 200:
                print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Interesting file: {base_url + d}")
        except: pass

def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        if "X-Frame-Options" not in headers:
            print(f"  [{Fore.RED}>{Style.RESET_ALL}] No X-Frame-Options (clickjacking possible)")
        if "Content-Security-Policy" not in headers:
            print(f"  [{Fore.RED}>{Style.RESET_ALL}] No CSP (XSS risk)")
        if "Strict-Transport-Security" not in headers:
            print(f"  [{Fore.RED}>{Style.RESET_ALL}] No HSTS (HTTPS downgrade possible)")
        if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
            print(f"  [{Fore.RED}>{Style.RESET_ALL}] CORS misconfigured (ACAO: *)")
        if "Set-Cookie" in headers:
            cookie = headers["Set-Cookie"]
            if "HttpOnly" not in cookie:
                print(f"  [{Fore.RED}>{Style.RESET_ALL}] Cookie without HttpOnly")
            if "Secure" not in cookie:
                print(f"  [{Fore.RED}>{Style.RESET_ALL}] Cookie without Secure")
    except: pass

# === CMS DETECTION + CVE CHECK ===
def detect_cms(base_url):
    print(f"  [{Fore.YELLOW}={Style.RESET_ALL}] CMS detection...")
    if not base_url.endswith("/"): base_url += "/"
    try:
        r = requests.get(base_url, timeout=5)
        content = r.text
        headers = str(r.headers)

        for cms, signs in CMS_SIGNATURES.items():
            for s in signs:
                if s.startswith("/"):
                    try:
                        test = requests.get(base_url + s.strip("/"), timeout=5)
                        if test.status_code == 200:
                            print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] CMS detected: {cms} ({base_url + s})")
                            version = extract_version(content, headers, cms)
                            check_cves(cms, version)
                            return
                    except: pass
                if s in content or s in headers:
                    print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] CMS detected: {cms}")
                    version = extract_version(content, headers, cms)
                    check_cves(cms, version)
                    return
    except: pass

def extract_version(content, headers, cms):
    version = None
    try:
        if cms == "WordPress":
            match = re.search(r"WordPress\s+([0-9\.]+)", content, re.I)
            if match: version = match.group(1)
        elif cms == "Joomla":
            match = re.search(r"Joomla\!?\s*([0-9\.]+)", content, re.I)
            if match: version = match.group(1)
        elif cms == "Drupal":
            match = re.search(r"Drupal\s+([0-9\.]+)", content, re.I)
            if match: version = match.group(1)
        elif cms == "Laravel":
            if "Laravel" in content:
                match = re.search(r"Laravel\s+([0-9\.]+)", content, re.I)
                if match: version = match.group(1)
    except: pass

    if version:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Version detected: {version}")
    else:
        print(f"  [{Fore.RED}-{Style.RESET_ALL}] Unable to detect exact version")
    return version

def check_cves(cms, version):
    if not version: return
    base_version = version.split(".")[0] + "." + version.split(".")[1] if "." in version else version
    if cms in CVE_DB and base_version in CVE_DB[cms]:
        print(f"  [{Fore.CYAN}>{Style.RESET_ALL}] Known vulnerabilities for {cms} {base_version}:")
        for vuln in CVE_DB[cms][base_version]:
            print(f"   - {vuln}")
    else:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] No known vulnerabilities found in the local database for {cms} {version}")

# === MAIN ===
def run(url):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n  [{Fore.GREEN}>>>{Style.RESET_ALL}] Auto Scan Vulnerabilities: {url}\n")
    detect_cms(url)
    test_sqli(url)
    test_xss(url)
    test_cmdi(url)
    test_ssti(url)
    test_traversal(url)
    test_redirect(url)
    check_sensitive_files(url)
    brute_force_dirs(url)
    check_headers(url)
