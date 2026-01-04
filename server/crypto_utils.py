import hashlib
import bcrypt
import argon2
import os

from models import HashMode
from config import ACTIVE_HASH_MODE, PEPPER_VALUE, PROTECTION_FLAGS

ph = argon2.PasswordHasher(
    time_cost=1,
    memory_cost=65536, 
    parallelism=1,
    type=argon2.Type.ID
)

def hash_password(password: str):
    if PROTECTION_FLAGS["pepper"]:
        password = PEPPER_VALUE + password

    if ACTIVE_HASH_MODE == HashMode.SHA256:
        # sha256 with salt
        salt = os.urandom(16).hex()
        combined = password + salt
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return hashed, salt, HashMode.SHA256
    
    elif ACTIVE_HASH_MODE == HashMode.BCRYPT:
        # bcrypt handles salt itself
        salt_bytes = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(password.encode(), salt_bytes)
        return hashed_bytes.decode(), None, HashMode.BCRYPT
    
    elif ACTIVE_HASH_MODE == HashMode.ARGON2:
        # argon2id
        hashed = ph.hash(password)
        return hashed, None, HashMode.ARGON2
    
    else:
        raise ValueError("bad mode")

def verify_password(stored_password, provided_password, salt, mode):
    if PROTECTION_FLAGS["pepper"]:
        provided_password = PEPPER_VALUE + provided_password
    
    if mode == HashMode.SHA256:
        combined = provided_password + salt
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return hashed == stored_password
    
    elif mode == HashMode.BCRYPT:
        try:
            return bcrypt.checkpw(provided_password.encode(), stored_password.encode())
        except:
            return False
            
    elif mode == HashMode.ARGON2:
        try:
            return ph.verify(stored_password, provided_password)
        except:
            return False
            
    return False
