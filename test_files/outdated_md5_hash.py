#outdated_md5_hash.py
import hashlib

data = b"password123"
hashed = hashlib.md5(data).hexdigest()
print("MD5 Hash:", hashed)
