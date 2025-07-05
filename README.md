# Open Redirect Super Power Scanner by Jass 🚀

![banner](https://img.shields.io/badge/OpenRedirectScanner-Powered%20by%20Jass-green?style=flat-square)

## 🎯 What is this tool?

**OpenRedirectScanner** is a powerful, advanced open redirect vulnerability scanner with severity classification, built in Python by Jass. It helps identify, classify, and report open redirects across multiple endpoints with **multithreaded** speed and **color-coded** severity display.  

✅ Classifies vulnerabilities as **Critical**, **Medium**, or **Low**  
✅ Supports bulk scanning with a target file (`-f`) or a single URL (`-u`)  
✅ Built-in **param scanning** for common redirect parameters  
✅ Supports `--clean` to filter only HTTP/HTTPS URLs  
✅ Supports `--export csv/json` for reporting  
✅ High–quality colored terminal output for **confirmed**, **safe**, and **error** results  
✅ Custom payloads to test advanced bypasses like `javascript://%250aalert(document.cookie)`  
✅ Fully multithreaded for faster scanning  
✅ Professional and easy to extend

---

## 🚀 How does it work?

The tool uses these common redirect parameters to fuzz:
- `next`
- `url`
- `redirect`
- `return`
- `to`
- `continue`

and tries multiple payloads like:
- `//evil.com`
- `https://evil.com`
- `//attacker.com`
- `javascript://%250aalert(document.cookie)`

It sends these payloads to each parameter of each target URL, then follows redirects and checks if the payload lands on an untrusted domain or triggers a `javascript:` scheme. Based on the response, it classifies the vulnerability as:

- **Critical** → payload executes JavaScript  
- **Medium** → external trusted domain redirect  
- **Low** → suspicious but less risky redirect  

---

## ⚡ Special Features

✅ Color–coded output:
- **Critical** → bold red  
- **Medium** → bold yellow  
- **Low** → bold cyan  
- confirmed vuln → always bold green  
- safe → white 

✅ Clean mode:
- use `--clean` to remove non-HTTP(S) targets automatically

✅ Export:
- use `--export csv` or `--export json` to store results

✅ Fully threaded:
- use `--threads N` to control concurrency

✅ False positive reduction:
- follows redirects completely to confirm the final landing page  
- handles network errors gracefully

---

## 🛠 Installation

```bash
git clone https://github.com/jaswanthjass/openredirectscanner.git
cd openredirectscanner
pip install -r requirements.txt

