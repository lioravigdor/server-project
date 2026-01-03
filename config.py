from models import HashMode

# group seed configuration
ID1 = 207031337
ID2 = 20723855
GROUP_SEED = ID1 ^ ID2

# hashing configuration
ACTIVE_HASH_MODE = HashMode.SHA256

# protection flags configuration
PROTECTION_FLAGS = {
    "pepper": True,
    "rate_limiting": True,
    "account_lockout": True
}

# pepper configuration
PEPPER_VALUE = "SecretPepper"

# rate limiting configuration
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60

# account lockout configuration
LOCKOUT_THRESHOLD = 3
LOCKOUT_DURATION_SECONDS = 20
