#test_aes_weak_modes.py
from Crypto.Cipher import AES

# AES in ECB mode (insecure mode)
key = b'sixteen byte key'
cipher = AES.new(key, AES.MODE_ECB)
