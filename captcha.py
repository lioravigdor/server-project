from config import PROTECTION_FLAGS, CAPTCHA_THRESHOLD, CAPTCHA_TOKEN

captcha_tracking = {}

def check_captcha_required(username):
    if not PROTECTION_FLAGS["captcha"]:
        return False
        
    attempts = captcha_tracking.get(username, 0)
    return attempts >= CAPTCHA_THRESHOLD

def increment_captcha_failures(username):
    if not PROTECTION_FLAGS["captcha"]:
        return
        
    captcha_tracking[username] = captcha_tracking.get(username, 0) + 1

def reset_captcha_failures(username):
    if username in captcha_tracking:
        del captcha_tracking[username]

def verify_captcha_token(token):
    return token == CAPTCHA_TOKEN
