import hashlib

data = b"important data"
hashed = hashlib.sha1(data).hexdigest()
print("SHA-1 Hash:", hashed)
