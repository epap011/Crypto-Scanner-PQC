#password_hashing_no_salt.py
import hashlib

# Hashing without salt
password = b"securepassword"
hashed_password = hashlib.sha256(password).hexdigest()
print("Password Hash without Salt:", hashed_password)
