from models import HashMode

# group seed configuration
ID1 = 207031337
ID2 = 207273855
GROUP_SEED = ID1 ^ ID2

# hashing configuration
ACTIVE_HASH_MODE = HashMode.SHA256

# protection flags (set via CLI: python main.py --protect pepper rate_limiting)
PROTECTION_FLAGS = {
    "pepper": False,
    "rate_limiting": False,
    "account_lockout": False,
    "captcha": False,
    "totp": False
}

# valid protection names for CLI validation
VALID_PROTECTIONS = list(PROTECTION_FLAGS.keys())

# pepper configuration
PEPPER_VALUE = "SecretPepper"

# rate limiting configuration
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60

# account lockout configuration
LOCKOUT_THRESHOLD = 10
LOCKOUT_DURATION_SECONDS = 20

# captcha configuration
CAPTCHA_THRESHOLD = 3
CAPTCHA_TOKEN = "captcha_token"
