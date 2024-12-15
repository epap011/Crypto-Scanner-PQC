#weak_rsa_key.py
from Crypto.PublicKey import RSA

key = RSA.generate(1024)
print("Weak RSA Key:", key.export_key().decode())
