# Password Authentication Server

**Group Seed:** 897878

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Start server (from server directory)
cd server

# No protections (default)
python main.py

# With specific protections
python main.py --protect pepper rate_limiting

# With all protections
python main.py --protect all
```

## Running Attacks

```bash
# Run brute force (new terminal)
python3 attacks/brute_forcer/brute_forcer.py -u weak_user_01

# Run password spray
python3 attacks/password_sprayer/password_sprayer.py
```

## Available Protections

`pepper`, `rate_limiting`, `account_lockout`, `captcha`, `totp`, `all`, `none`
