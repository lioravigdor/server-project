import json
import time
import sqlite3
import pyotp
from fastapi import FastAPI, Body, HTTPException, status
from config import GROUP_SEED, PROTECTION_FLAGS, CAPTCHA_TOKEN, ACTIVE_HASH_MODE

from models import UserRegister, UserLogin, AuthResult, UserLoginTotp
from crypto_utils import hash_password, verify_password
from rate_limit import check_rate_limit
from lockout import check_lockout, handle_failed_attempt, reset_failed_attempts
from captcha import check_captcha_required, increment_captcha_failures, reset_captcha_failures, verify_captcha_token

app = FastAPI()

def get_latency(start_time):
    return (time.time() - start_time) * 1000

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, hashed_password TEXT, salt TEXT, hash_mode TEXT, totp_secret TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_attempt(username, mode, flags, result, latency):
    entry = {
        "timestamp": time.time(),
        "username": username,
        "hash_mode": mode,
        "protection_flags": flags,
        "result": result,
        "latency_ms": latency,
        "group_seed": GROUP_SEED
    }
    with open("attempts.log", "a") as f:
        f.write(json.dumps(entry) + "\n")

@app.post("/register")
def register(user_data: UserRegister):
    username = user_data.username
    password = user_data.password
    
    if not username or not password:
         raise HTTPException(status_code=400, detail="Missing username or password")

    hashed, salt, mode = hash_password(password)
    
    totp_secret = None
    if PROTECTION_FLAGS.get("totp"):
        totp_secret = pyotp.random_base32()

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, hashed_password, salt, hash_mode, totp_secret) VALUES (?, ?, ?, ?, ?)",
                  (username, hashed, salt, mode, totp_secret)) 
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="User already exists")
    
    conn.close()
    
    response = {"message": "User registered"}
    if totp_secret:
        response["totp_secret"] = totp_secret
        
    return response

@app.post("/login")
def login(user_data: UserLogin):
    if not check_rate_limit(user_data.username):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    start_time = time.time()
    username = user_data.username
    
    is_locked, remaining_time = check_lockout(username)
    if is_locked:
        latency = get_latency(start_time)
        log_attempt(username, None, PROTECTION_FLAGS, AuthResult.FAILURE, latency)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=f"Account locked. Try again in {int(remaining_time)} seconds."
        )

    if check_captcha_required(username):
        if not user_data.captcha_token:
            latency = get_latency(start_time)
            log_attempt(username, None, PROTECTION_FLAGS, AuthResult.FAILURE, latency)
            raise HTTPException(status_code=400, detail="Captcha required")
        
        if not verify_captcha_token(user_data.captcha_token):
            raise HTTPException(status_code=400, detail="Invalid CAPTCHA token")

    password = user_data.password
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT hashed_password, salt, hash_mode, totp_secret FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    
    result = AuthResult.FAILURE

    if user:
         stored_password = user[0]
         salt = user[1]
         mode = user[2]
         totp_secret = user[3]
         
         if verify_password(stored_password, password, salt, mode):
             result = AuthResult.SUCCESS
             reset_failed_attempts(username)
             reset_captcha_failures(username)
             
             if totp_secret and PROTECTION_FLAGS.get("totp"):
                 latency = get_latency(start_time)
                 log_attempt(username, ACTIVE_HASH_MODE, PROTECTION_FLAGS, AuthResult.FAILURE, latency)
                 return {"message": "2FA Required"}
         else:
             handle_failed_attempt(username)
             increment_captcha_failures(username)
    else:
        handle_failed_attempt(username)
        increment_captcha_failures(username)
    
    latency = get_latency(start_time)
    log_attempt(username, ACTIVE_HASH_MODE, PROTECTION_FLAGS, result, latency)
    
    if result == AuthResult.SUCCESS:
        return {"message": "Login successful"}
    
    return {"message": "Login failed"}

@app.post("/login_totp")
def login_totp(user_data: UserLoginTotp):
    if not PROTECTION_FLAGS.get("totp"):
        raise HTTPException(status_code=404, detail="TOTP feature disabled")

    start_time = time.time()
    username = user_data.username
    totp_code = user_data.totp_code

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT totp_secret, hash_mode FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    result = AuthResult.FAILURE
    if user:
        totp_secret = user[0]        
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
             result = AuthResult.SUCCESS
    
    latency = get_latency(start_time)
    log_attempt(username, ACTIVE_HASH_MODE, PROTECTION_FLAGS, result, latency)

    if result == AuthResult.SUCCESS:
        return {"message": "Login successful"}
    
    raise HTTPException(status_code=401, detail="Invalid TOTP code")

@app.get("/admin/get_captcha_token")
def get_captcha_token(group_seed: int):
    if group_seed == GROUP_SEED:
        return {"captcha_token": CAPTCHA_TOKEN}
    
    raise HTTPException(status_code=403, detail="Invalid group seed")
