#cbc_static_iv.py
from Crypto.Cipher import AES

key = b'16bytekey1234567'
iv = b'staticIV12345678'  # Static IV is insecure
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(b'16byteblock12345')
print("AES CBC Encrypted with Static IV:", encrypted)
