# Server

```bash
# Start with defaults (sha256, no protections)
python main.py

# Different hash algorithm
python main.py --hash bcrypt
python main.py --hash argon2

# Enable specific protections
python main.py --protect pepper rate_limiting

# Combine hash and protections
python main.py --hash argon2 --protect all

# Custom host/port with reload
python main.py --hash bcrypt --protect captcha --port 8080 --reload
```

## CLI Options

```
--hash       Hash algorithm: sha256, bcrypt, argon2 (default: sha256)
--protect    Enable protections: pepper, rate_limiting, account_lockout, captcha, totp, all, none
--host       Host to bind (default: 127.0.0.1)
--port       Port to bind (default: 8000)
--reload     Enable auto-reload for development
```

## Available Protections

- `pepper` - Adds secret pepper to password hashing
- `rate_limiting` - Limits login attempts per time window
- `account_lockout` - Locks account after failed attempts
- `captcha` - Requires CAPTCHA after failed attempts
- `totp` - Enables two-factor authentication
