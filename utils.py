"""
Shared utilities for poc-scripts.
"""

try:
    import requests
except ImportError:
    import sys
    sys.exit("Missing dependencies. Run: pip install -r requirements.txt")


def build_session(cookies: str | None, user_agent: str = "PoC/1.0 (educational)") -> "requests.Session":
    """Create a requests.Session with optional cookie injection."""
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    if cookies:
        for pair in cookies.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                session.cookies.set(k.strip(), v.strip())
    return session
