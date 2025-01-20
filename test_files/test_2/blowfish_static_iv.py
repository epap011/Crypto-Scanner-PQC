#blowfish_static_iv.py
from Crypto.Cipher import Blowfish

key = b'SecureKey1234567'
iv = b'StaticIV123456'  # Insecure static IV
cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
encrypted = cipher.encrypt(b'sampledata')
print("Blowfish Encrypted with Static IV:", encrypted)
