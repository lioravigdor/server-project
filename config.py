from enum import Enum

class HashMode(str, Enum):
    SHA256 = 'SHA256'
    BCRYPT = 'BCRYPT'
    ARGON2 = 'ARGON2'

# group seed configuration
ID1 = 207031337
ID2 = 987654321 # TODO - change to roei id
GROUP_SEED = ID1 ^ ID2

# hashing configuration
ACTIVE_HASH_MODE = HashMode.SHA256

# protection flags configuration
PEPPER_VALUE = "SecretPepper"
PROTECTION_FLAGS = {
    "pepper": True
}
