#blowfish_insecure.py
from Crypto.Cipher import Blowfish

key = b'ShortKey'  # Insecure short key
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
encrypted = cipher.encrypt(b'sampledata')  # ECB mode also insecure
print("Blowfish Encrypted:", encrypted)
