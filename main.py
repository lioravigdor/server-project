import json
import time
import sqlite3
from fastapi import FastAPI, Body, HTTPException
from config import GROUP_SEED, PROTECTION_FLAGS

from models import UserRegister, UserLogin, AuthResult
from crypto_utils import hash_password, verify_password

app = FastAPI()

def get_latency(start_time):
    return (time.time() - start_time) * 1000

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, hashed_password TEXT, salt TEXT, hash_mode TEXT)''')
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

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, hashed_password, salt, hash_mode) VALUES (?, ?, ?, ?)",
                  (username, hashed, salt, mode)) 
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="User already exists")
    
    conn.close()
    return {"message": "User registered"}

@app.post("/login")
def login(user_data: UserLogin):
    start_time = time.time()
    username = user_data.username
    password = user_data.password
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT hashed_password, salt, hash_mode FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    
    result = AuthResult.FAILURE
    mode = None

    if user:
         stored_password = user[0]
         salt = user[1]
         mode = user[2]
         
         if verify_password(stored_password, password, salt, mode):
             result = AuthResult.SUCCESS
    
    latency = get_latency(start_time)
    log_attempt(username, mode, PROTECTION_FLAGS, result, latency)
    
    if result == AuthResult.SUCCESS:
        return {"message": "Login successful"}
    
    return {"message": "Login failed"}
