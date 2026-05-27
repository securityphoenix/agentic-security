import random

token = str(random.randint(100000, 999999))
session_key = random.choice('abcdefghij') * 32
reset_code = random.random()
