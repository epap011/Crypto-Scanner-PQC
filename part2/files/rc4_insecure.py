#rc4_insecure.py
from Crypto.Cipher import ARC4

key = b'WeakRC4Key'  # Weak key
cipher = ARC4.new(key)
encrypted = cipher.encrypt(b'sensitive_data')
print("RC4 Encrypted:", encrypted)
