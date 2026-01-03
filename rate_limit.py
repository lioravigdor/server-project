import time
from config import PROTECTION_FLAGS, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS

login_attempts = {}

def check_rate_limit(username):
    if not PROTECTION_FLAGS["rate_limiting"]:
        return True
        
    current_time = time.time()
    if username not in login_attempts:
        login_attempts[username] = []
        
    login_attempts[username] = [t for t in login_attempts[username] if current_time - t < RATE_LIMIT_WINDOW_SECONDS]
    
    if len(login_attempts[username]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
        
    login_attempts[username].append(current_time)
    return True
