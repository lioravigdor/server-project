# Brute Forcer

```bash
# Run brute force against a user
python3 brute_forcer.py -u weak_user_01
```

## Options

| Flag | Description |
|------|-------------|
| `-u, --username` | Target user (required) |
| `-w, --wordlist` | Password file (default: wordlist.txt) |
| `--max-attempts` | Stop after N attempts (default: 50000) |
| `--time-limit` | Stop after N seconds (default: 7200) |
| `-o, --output` | Save results to JSON file |
| `--base-url` | Server URL (default: http://127.0.0.1:8000) |
| `--with-totp` | Enable TOTP automation (use stored secrets) |

