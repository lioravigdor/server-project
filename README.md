# Password Authentication Server

**Group Seed:** 897878

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Start server (users are auto-loaded from server/users.json)
cd server && uvicorn main:app --reload

# Run brute force (new terminal)
python3 attacks/brute_forcer/brute_forcer.py -u weak_user_01

# Run password spray
python3 attacks/password_sprayer/password_sprayer.py
```
