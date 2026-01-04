# Password Sprayer

```bash
# Spray common passwords against all users
python3 password_sprayer.py
```

## Options

| Flag | Description |
|------|-------------|
| `-p, --passwords` | Passwords file (default: common_passwords.txt) |
| `--users-json` | Path to users.json |
| `--max-attempts` | Stop after N attempts (default: 50000) |
| `--time-limit` | Stop after N seconds (default: 7200) |
| `-o, --output` | Save results to JSON file |
| `--base-url` | Server URL (default: http://127.0.0.1:8000) |
| `--with-totp` | Enable TOTP automation |

