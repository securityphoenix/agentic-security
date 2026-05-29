import hashlib
import requests
from Crypto.Cipher import DES, AES, ARC4

# BUG: MD5 in security context.
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# BUG: SHA1 used.
def fingerprint(b):
    return hashlib.sha1(b).hexdigest()

# BUG: requests with verify=False.
def fetch_internal(url):
    return requests.get(url, verify=False)

# BUG: DES cipher.
def encrypt(data, key):
    c = DES.new(key, DES.MODE_CBC)
    return c.encrypt(data)

# BUG: AES ECB mode.
def encrypt_ecb(data, key):
    c = AES.new(key, AES.MODE_ECB)
    return c.encrypt(data)

# BUG: PBKDF2 too few iterations.
def derive(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)

# BUG: PyJWT with algorithms=['none'].
import jwt
def verify_token(t, k):
    return jwt.decode(t, k, algorithms=['none'])
