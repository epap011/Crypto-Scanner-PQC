#weak_pbkdf2.py
from hashlib import pbkdf2_hmac

password = b"weak_password"
salt = b"random_salt"
iterations = 1000  # Insufficient iterations

key = pbkdf2_hmac('sha256', password, salt, iterations)
print("Derived Key with Weak PBKDF2:", key)
