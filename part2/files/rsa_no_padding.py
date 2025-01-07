#rsa_no_padding.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

key = RSA.generate(2048)
cipher = PKCS1_v1_5.new(key)  # RSA without padding is insecure
plaintext = b"Sensitive data"
ciphertext = cipher.encrypt(plaintext)
print("RSA Encrypted without Padding:", ciphertext)
