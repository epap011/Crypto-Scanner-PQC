#hmac_with_md5_sha1.py
import hmac
import hashlib

key = b"secret_key"
message = b"important_message"

# Using MD5 and SHA-1 in HMAC (deprecated)
hmac_md5 = hmac.new(key, message, hashlib.md5).hexdigest()
hmac_sha1 = hmac.new(key, message, hashlib.sha1).hexdigest()

print("HMAC MD5:", hmac_md5)
print("HMAC SHA-1:", hmac_sha1)
