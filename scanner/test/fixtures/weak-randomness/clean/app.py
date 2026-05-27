import secrets

token = secrets.token_hex(32)
session_key = secrets.token_urlsafe(32)
reset_code = secrets.randbelow(999999)
