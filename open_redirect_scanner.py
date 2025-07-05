#!/usr/bin/env python3
# Author: Jass

import requests
import argparse
import threading
import sys
import urllib.parse
import time
import csv
import json
from datetime import datetime
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# default params
default_params = ["next", "url", "redirect", "return", "to", "continue"]
default_payloads = [
    "//evil.com",
    "https://evil.com",
    "//attacker.com",
    "javascript://%250aalert(document.cookie)"
]

results = []
lock = threading.Lock()

def banner():
    print(colored("""
    
.s5SSSs.                                    .s5SSSs.                                                                      .s5SSSs.                                
      SS. .s5SSSs.  .s5SSSs.  .s    s.            SS. .s5SSSs.  .s5SSSs.  s.  .s5SSSs.  .s5SSSs.  .s5SSSs.  .s5SSSSs.           SS. .s5SSSs.  .s5SSSs.  .s    s.  
sS    S%S       SS.       SS.       SS.     sS    S%S       SS.       SS. SS.       SS.       SS.       SS.    SSS        sS    `:;       SS.       SS.       SS. 
SS    S%S sS    S%S sS    `:; sSs.  S%S     SS    S%S sS    `:; sS    S%S S%S sS    S%S sS    `:; sS    `:;    S%S        SS        sS    `:; sS    S%S sSs.  S%S 
SS    S%S SS .sS::' SSSs.     SS `S.S%S     SS .sS;:' SSSs.     SS    S%S S%S SS .sS;:' SSSs.     SS           S%S        `:;;;;.   SS        SSSs. S%S SS `S.S%S 
SS    S%S SS        SS        SS  `sS%S     SS    ;,  SS        SS    S%S S%S SS    ;,  SS        SS           S%S              ;;. SS        SS    S%S SS  `sS%S 
SS    `:; SS        SS        SS    `:;     SS    `:; SS        SS    `:; `:; SS    `:; SS        SS           `:;              `:; SS        SS    `:; SS    `:; 
SS    ;,. SS        SS    ;,. SS    ;,.     SS    ;,. SS    ;,. SS    ;,. ;,. SS    ;,. SS    ;,. SS    ;,.    ;,.        .,;   ;,. SS    ;,. SS    ;,. SS    ;,. 
`:;;;;;:' `:        `:;;;;;:' :;    ;:'     `:    ;:' `:;;;;;:' ;;;;;;;:' ;:' `:    ;:' `:;;;;;:' `:;;;;;:'    ;:'        `:;;;;;:' `:;;;;;:' :;    ;:' :;    ;:' 

                                                                                                                                                                  
    💥 Open Redirect Super Power Scanner 💥  by Jass
""", "cyan", attrs=["bold"]))

def scan_url(url, param, payload):
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme.startswith("http"):
            lock.acquire()
            print(colored(f"⚠ SKIPPED: {url} (invalid scheme)", "yellow", attrs=["bold"]))
            lock.release()
            return
        
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        q = urllib.parse.parse_qs(parsed.query)
        q[param] = payload
        new_query = urllib.parse.urlencode(q, doseq=True)
        test_url = f"{base}?{new_query}"

        try:
            r = requests.get(test_url, allow_redirects=False, timeout=10, verify=False)
        except Exception as e:
            lock.acquire()
            print(colored(f"⚠ ERROR: {url} - {e}", "red", attrs=["bold"]))
            lock.release()
            return
        
        location = r.headers.get("Location", "")
        severity = "Low"
        if payload.startswith("javascript:"):
            severity = "Critical"
        elif "evil" in payload or "attacker" in payload:
            severity = "Medium"

        if location and (
            "evil" in location
            or "attacker" in location
            or location.startswith("javascript:")
            or "//" in location
        ):
            lock.acquire()
            # vuln header with color
            severity_color = "red" if severity == "Critical" else "yellow" if severity == "Medium" else "cyan"
            print(
                colored("✅ 💥 CONFIRMED VULN", "green", attrs=["bold"])
                + f" ("
                + colored(severity, severity_color, attrs=["bold"])
                + "):"
            )
            # Full + redirects to
            print(colored(f"  Full: {test_url}", "green", attrs=["bold"]))
            print(colored(f"  Redirects to: {location}", "green", attrs=["bold"]))
            results.append({
                "target": url,
                "param": param,
                "payload": payload,
                "vulnerable_url": test_url,
                "redirects_to": location,
                "severity": severity,
                "status": r.status_code,
            })
            lock.release()
        else:
            lock.acquire()
            print(colored(f"🛡 SAFE: {parsed.netloc} [param: {param}]", "cyan"))
            lock.release()

    except Exception as e:
        lock.acquire()
        print(colored(f"⚠ ERROR: {url} - {e}", "red", attrs=["bold"]))
        lock.release()

def worker(urls, params, payloads):
    for url in urls:
        for param in params:
            for payload in payloads:
                scan_url(url, param, payload)

def main():
    parser = argparse.ArgumentParser(
        description="💥 Open Redirect Super Power Scanner by Jass",
        epilog="Enjoy hacking responsibly! ~Jass",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-f", "--file", help="file with list of urls/domains to scan")
    parser.add_argument("-u", "--url", help="single url to scan")
    parser.add_argument("--threads", type=int, default=10, help="number of threads")
    parser.add_argument("--export", choices=["csv", "json"], help="export results to csv/json")
    parser.add_argument("--clean", action="store_true", help="clean file to only valid http(s) targets")
    parser.add_argument("-v", "--version", action="version", version="OpenRedirectScanner by Jass v2.0")
    args = parser.parse_args()

    banner()

    targets = []
    if args.file:
        with open(args.file) as f:
            lines = [line.strip() for line in f if line.strip()]
            if args.clean:
                cleaned = [l for l in lines if l.startswith("http://") or l.startswith("https://")]
                print(colored(f"🧹 Cleaning targets to include only valid HTTP/HTTPS...", "blue"))
                print(colored(f"✅ Cleaned targets: {len(cleaned)} valid", "green"))
                targets.extend(cleaned)
            else:
                targets.extend(lines)
    if args.url:
        targets.append(args.url)

    if not targets:
        parser.print_help()
        sys.exit(1)

    print(colored(f"🚀 Starting Open Redirect Scan on {len(targets)} targets", "cyan"))
    print(colored(f"🛠 Params: {default_params}", "magenta"))
    print(colored(f"🎯 Payloads: {default_payloads}", "magenta"))
    print("────────────────────────────────────────────")

    chunk_size = max(1, len(targets) // args.threads)
    threads = []

    for i in range(0, len(targets), chunk_size):
        chunk = targets[i:i+chunk_size]
        t = threading.Thread(target=worker, args=(chunk, default_params, default_payloads))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # export
    if args.export == "csv":
        fname = f"redirect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(fname, "w", newline='') as csvfile:
            fieldnames = ["target", "param", "payload", "vulnerable_url", "redirects_to", "severity", "status"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(colored(f"📄 CSV saved to {fname}", "blue"))
    elif args.export == "json":
        fname = f"redirect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w") as jsonfile:
            json.dump(results, jsonfile, indent=2)
        print(colored(f"📄 JSON saved to {fname}", "blue"))

    confirmed = len([r for r in results if r])
    print(colored(f"\n🎉 Done! Confirmed: {confirmed} | Safe: {len(targets)-confirmed}", "green", attrs=["bold"]))

if __name__ == "__main__":
    main()
