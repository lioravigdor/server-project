# Password Authentication Server

**Group Seed:** 897878

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Start server (from server directory)
cd server

# Default (sha256, no protections)
python main.py

# With bcrypt hashing
python main.py --hash bcrypt

# With argon2 and protections
python main.py --hash argon2 --protect pepper rate_limiting

# All protections enabled
python main.py --protect all
```

## Running Attacks

```bash
# Run brute force (new terminal)
python3 attacks/brute_forcer/brute_forcer.py -u weak_user_01

# Run password spray
python3 attacks/password_sprayer/password_sprayer.py
```

## CLI Options

- `--hash` - sha256, bcrypt, argon2 (default: sha256)
- `--protect` - pepper, rate_limiting, account_lockout, captcha, totp, all, none
