import time
from config import PROTECTION_FLAGS, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS

login_attempts = {}

def check_rate_limit(ip_address):
    if not PROTECTION_FLAGS["rate_limiting"]:
        return True
        
    current_time = time.time()
    if ip_address not in login_attempts:
        login_attempts[ip_address] = []
        
    login_attempts[ip_address] = [t for t in login_attempts[ip_address] if current_time - t < RATE_LIMIT_WINDOW_SECONDS]
    
    if len(login_attempts[ip_address]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
        
    login_attempts[ip_address].append(current_time)
    return True
