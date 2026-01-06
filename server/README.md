# Server

```bash
# Start with no protections (default)
python main.py

# Enable specific protections
python main.py --protect pepper rate_limiting

# Enable all protections
python main.py --protect all

# Custom host/port with reload
python main.py --protect captcha account_lockout --port 8080 --reload
```

## Available Protections

- `pepper` - Adds secret pepper to password hashing
- `rate_limiting` - Limits login attempts per time window
- `account_lockout` - Locks account after failed attempts
- `captcha` - Requires CAPTCHA after failed attempts
- `totp` - Enables two-factor authentication

## CLI Options

```
--protect    Enable protections (pepper, rate_limiting, account_lockout, captcha, totp, all, none)
--host       Host to bind (default: 127.0.0.1)
--port       Port to bind (default: 8000)
--reload     Enable auto-reload for development
```
