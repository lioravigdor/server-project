import time
from config import PROTECTION_FLAGS, LOCKOUT_THRESHOLD, LOCKOUT_DURATION_SECONDS

lockout_tracking = {}

def check_lockout(username):
    if not PROTECTION_FLAGS["account_lockout"]:
        return False, 0
    
    if username not in lockout_tracking:
        return False, 0
    
    data = lockout_tracking[username]
    lockout_until = data.get('lockout_until', 0)
    
    current_time = time.time()
    if lockout_until > current_time:
        return True, lockout_until - current_time
    
    return False, 0

def handle_failed_attempt(username):
    if not PROTECTION_FLAGS["account_lockout"]:
        return

    if username not in lockout_tracking:
        lockout_tracking[username] = {'attempts': 0, 'lockout_until': 0}
    
    data = lockout_tracking[username]
    current_time = time.time()
    
    if data['lockout_until'] > 0 and data['lockout_until'] < current_time:
        data['attempts'] = 0
        data['lockout_until'] = 0
        
    data['attempts'] += 1
    
    if data['attempts'] >= LOCKOUT_THRESHOLD:
        data['lockout_until'] = current_time + LOCKOUT_DURATION_SECONDS

def reset_failed_attempts(username):
    if username in lockout_tracking:
        del lockout_tracking[username]
