#!/usr/bin/env python3
"""
Initialize test users by reading from users.json and registering via API.
"""

import json
import argparse
import requests
from pathlib import Path


def load_users(json_path: str) -> dict:
    """Load users from JSON file."""
    with open(json_path, 'r') as f:
        return json.load(f)


def register_user(base_url: str, username: str, password: str) -> tuple[bool, str]:
    """
    Register a single user via the /register endpoint.
    Returns (success: bool, message: str)
    """
    try:
        response = requests.post(
            f"{base_url}/register",
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            totp_secret = data.get("totp_secret")
            if totp_secret:
                return True, f"Registered (TOTP: {totp_secret})"
            return True, "Registered"
        else:
            detail = response.json().get("detail", response.text)
            return False, f"Failed: {detail}"
            
    except requests.exceptions.ConnectionError:
        return False, "Connection error - is the server running?"
    except Exception as e:
        return False, f"Error: {str(e)}"


def main():
    parser = argparse.ArgumentParser(description="Initialize test users from users.json")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Base URL of the server (default: http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--users-file",
        default=str(Path(__file__).parent / "users.json"),
        help="Path to users.json file (default: ./users.json)"
    )
    args = parser.parse_args()

    # Load users
    print(f"Loading users from: {args.users_file}")
    data = load_users(args.users_file)
    
    group_seed = data.get("group_seed")
    users = data.get("users", [])
    
    print(f"Group Seed: {group_seed}")
    print(f"Total users to register: {len(users)}")
    print("-" * 50)

    # Track results
    success_count = 0
    fail_count = 0
    totp_secrets = {}

    # Register each user
    for user in users:
        username = user["username"]
        password = user["password"]
        category = user["category"]
        
        success, message = register_user(args.base_url, username, password)
        
        status = "✓" if success else "✗"
        print(f"[{status}] {username} ({category}): {message}")
        
        if success:
            success_count += 1
            # Extract TOTP secret if present
            if "TOTP:" in message:
                totp_secret = message.split("TOTP: ")[1].rstrip(")")
                totp_secrets[username] = totp_secret
        else:
            fail_count += 1

    # Summary
    print("-" * 50)
    print(f"Results: {success_count} succeeded, {fail_count} failed")
    
    # Save TOTP secrets if any were generated
    if totp_secrets:
        secrets_file = Path(args.users_file).parent / "totp_secrets.json"
        with open(secrets_file, 'w') as f:
            json.dump(totp_secrets, f, indent=2)
        print(f"TOTP secrets saved to: {secrets_file}")


if __name__ == "__main__":
    main()

