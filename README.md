# Password Authentication Server

**Group Seed:** 897878

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Start server
cd server && uvicorn main:app --reload

# Create test users (new terminal)
python3 initializer/init_users.py

# Run brute force (new terminal)
python3 attacks/brute_forcer/brute_forcer.py -u weak_user_01

# Run password spray
python3 attacks/password_sprayer/password_sprayer.py
```
