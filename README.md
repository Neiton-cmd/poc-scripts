# poc-scripts

A collection of Python proof-of-concept (PoC) scripts for demonstrating and testing common web application vulnerabilities.

> **⚠️ DISCLAIMER: For educational and research purposes only.**  
> These scripts are intended to help security professionals understand how vulnerabilities work so they can build better defences. **Never run these scripts against systems you do not own or have explicit written permission to test.** Unauthorised use is illegal and unethical.

---

## Covered Vulnerabilities

| Directory | Vulnerability | Description |
|-----------|--------------|-------------|
| [`sqli/`](sqli/) | SQL Injection | Error-based and boolean-blind SQLi detection |
| [`xss/`](xss/) | Cross-Site Scripting (XSS) | Reflected and stored XSS payload testing |
| [`cmd_injection/`](cmd_injection/) | Command Injection | OS command injection via user-controlled input |
| [`path_traversal/`](path_traversal/) | Path Traversal | Directory traversal / local file inclusion |
| [`ssrf/`](ssrf/) | Server-Side Request Forgery | SSRF via URL parameter manipulation |

---

## Requirements

- Python 3.8+
- Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Each script accepts a `--url` argument pointing at a **deliberately vulnerable** test application (e.g., [DVWA](https://github.com/digininja/DVWA), [WebGoat](https://github.com/WebGoat/WebGoat), or a local lab).

```bash
# SQL Injection
python sqli/sqli_poc.py --url "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"

# Cross-Site Scripting
python xss/xss_poc.py --url "http://localhost/dvwa/vulnerabilities/xss_r/?name=test"

# Command Injection
python cmd_injection/cmd_injection_poc.py --url "http://localhost/dvwa/vulnerabilities/exec/" --param ip

# Path Traversal
python path_traversal/path_traversal_poc.py --url "http://localhost/dvwa/vulnerabilities/fi/?page=file1.php"

# SSRF
python ssrf/ssrf_poc.py --url "http://localhost/dvwa/vulnerabilities/ssrf/" --param url
```

Run any script with `-h` for full usage information.

---

## Project Structure

```
poc-scripts/
├── README.md
├── requirements.txt
├── utils.py
├── sqli/
│   └── sqli_poc.py
├── xss/
│   └── xss_poc.py
├── cmd_injection/
│   └── cmd_injection_poc.py
├── path_traversal/
│   └── path_traversal_poc.py
└── ssrf/
    └── ssrf_poc.py
```

---

## Legal

Use responsibly. The authors accept no liability for misuse. Always obtain explicit written permission before testing any system you do not own.