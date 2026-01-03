from pydantic import BaseModel
from enum import Enum

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class AuthResult(Enum):
    SUCCESS = "Success"
    FAILURE = "Failure"
