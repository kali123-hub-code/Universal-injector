import requests
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

init(autoreset=True)

def show_banner():
    print(Fore.RED + r"""
     █████╗ ██╗   ██╗ ██████╗ ██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██████╗ 
    ██╔══██╗██║   ██║██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗
    ███████║██║   ██║██║   ██║██║   ██║██║  ██║█████╗  ██████╔╝██║   ██║██████╔╝
    ██╔══██║██║   ██║██║   ██║██║   ██║██║  ██║██╔══╝  ██╔═══╝ ██║   ██║██╔═══╝ 
    ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝██████╔╝███████╗██║     ╚██████╔╝██║     
    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚═╝      ╚═════╝ ╚═╝     

    """ + Fore.CYAN + Style.BRIGHT + "⚔️ Universal Injector - Fast Web Vulnerability Scanner ⚔️" + Fore.YELLOW + f"""
    🔍 Made by: Naveed Qadir | Bug Hunter | Cyber Security Student
    📂 GitHub: github.com/naveedqadir666
    """ + Fore.WHITE)

def load_payloads(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[-] Wordlist file not found: {file_path}")
        return []

def detect_vulnerability(payload, response_text, elapsed):
    findings = []

    if payload in response_text:
        findings.append("XSS")

    sql_errors = ["sql syntax", "mysql", "syntax error", "unclosed quotation", "psql", "native client", "ORA-"]
    if any(err in response_text.lower() for err in sql_errors):
        findings.append("SQLi")

    if "root:x:" in response_text or "boot.ini" in response_text:
        findings.append("Path Traversal")

    if "uid=" in response_text or "No such file" in response_text:
        findings.append("Command Injection")

    if "MongoError" in response_text or "ldap" in response_text.lower():
        findings.append("NoSQL/LDAP")

    if elapsed > 5:
        findings.append("Blind Injection (Timing)")

    return findings

def save_result(full_url, param_key, payload, issues):
    with open("vuln_results.txt", "a") as f:
        f.write(f"{param_key} => {payload} [{', '.join(issues)}]\n")
        f.write(f"URL: {full_url}\n\n")

def test_payload(method, url_base, param_key, original_params, payload, headers, verbose):
    test_params = original_params.copy()
    test_params[param_key] = payload

    try:
        if method == "GET":
            full_url = f"{url_base}?{urlencode(test_params, doseq=True)}"
            start = time.time()
            response = requests.get(full_url, headers=headers, timeout=10)
        else:  # POST
            full_url = url_base
            start = time.time()
            response = requests.post(full_url, data=test_params, headers=headers, timeout=10)
        elapsed = time.time() - start

        status = response.status_code
        issues = detect_vulnerability(payload, response.text, elapsed)
        tag = f" [{', '.join(issues)}]" if issues else ""

        # Color by status code
        if status >= 500:
            color = Fore.RED
        elif status == 403:
            color = Fore.YELLOW
        elif status == 200:
            color = Fore.GREEN
        else:
            color = Fore.WHITE

        if verbose or issues:
            print(color + f"[{status}] {param_key} => {payload}{tag}")

        if issues:
            save_result(full_url, param_key, payload, issues)

    except Exception as e:
        print(Fore.RED + f"[!] Error on {url_base}: {e}")

def scan_all(url, payloads, method="GET", headers=None, threads=10, verbose=False):
    headers = headers or {}
    parsed = urlparse(url)
    url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    original_params = parse_qs(parsed.query)

    if not original_params:
        print(Fore.RED + "[-] No parameters found in URL.")
        return

    print(Fore.BLUE + f"[+] Scanning: {url} with method {method.upper()}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for payload in payloads:
            for param in original_params:
                executor.submit(test_payload, method, url_base, param, original_params, payload, headers, verbose)

def main():
    show_banner()
    print(Style.BRIGHT + Fore.MAGENTA + "=== Fast Injection Scanner ===\n")

    url = input("[?] Enter target URL with GET params: ").strip()
    wordlist = input("[?] Enter wordlist path: ").strip()
    method = input("[?] Choose HTTP method (GET/POST): ").strip().upper()

    headers_input = input("[?] Enter headers as JSON (or leave blank): ").strip()
    try:
        headers = json.loads(headers_input) if headers_input else {}
    except json.JSONDecodeError:
        print(Fore.RED + "[-] Invalid JSON for headers.")
        headers = {}

    verbose = input("[?] Verbose mode? (y/N): ").strip().lower() == "y"

    payloads = load_payloads(wordlist)
    if payloads:
        scan_all(url, payloads, method=method, headers=headers, verbose=verbose)

if __name__ == "__main__":
    main()
        

        # ✅ Always print reflection test result
        print(f"Testing {param_key} => {payload} | in response? {'YES' if payload in response.text else 'NO'}")
