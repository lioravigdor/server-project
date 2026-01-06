#!/usr/bin/env python3
"""Clean environment - removes database and generated files."""

import os
from pathlib import Path

ROOT = Path(__file__).parent

FILES_TO_DELETE = [
    ROOT / "users.db",
    ROOT / "server" / "users.db",
    ROOT / "server" / "totp_secrets.json",
    ROOT / "server" / "attempts.log",
]

def main():
    print("This will delete:")
    for f in FILES_TO_DELETE:
        status = "exists" if f.exists() else "not found"
        print(f"  - {f.relative_to(ROOT)} ({status})")
    
    response = input("\nAre you sure? [N/y]: ").strip().lower()
    
    if response != 'y':
        print("Cancelled.")
        return
    
    deleted = 0
    for f in FILES_TO_DELETE:
        if f.exists():
            os.remove(f)
            print(f"Deleted: {f.relative_to(ROOT)}")
            deleted += 1
    
    print(f"\nDone. {deleted} file(s) deleted.")


if __name__ == "__main__":
    main()

