from pydantic import BaseModel
from enum import Enum

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class AuthResult(str, Enum):
    SUCCESS = "Success"
    FAILURE = "Failure"
    LOCKED = "Locked"

class HashMode(str, Enum):
    SHA256 = 'SHA256'
    BCRYPT = 'BCRYPT'
    ARGON2 = 'ARGON2'