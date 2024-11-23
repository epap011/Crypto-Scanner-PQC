import hashlib

# SHA-1 (deprecated)
hash1 = hashlib.sha1(b"data").hexdigest()

# SHA-224 (deprecated variant of SHA-2)
hash224 = hashlib.sha224(b"data").hexdigest()
