# Password Authentication Server

**Group Seed:** 897878

## How to Run

```bash
# Install dependencies
pip3 install -r requirements.txt

# Start server
cd server
uvicorn main:app --reload

# Initialize test users (in a new terminal)
python3 initializer/init_users.py
```
