#aes_gcm_no_tag_check.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(b"important_message")

# Insecure: No tag verification during decryption
decrypt_cipher = AES.new(key, AES.MODE_GCM, cipher.nonce)
decrypted = decrypt_cipher.decrypt(ciphertext)  # Tag not verified
print("Decrypted without Tag Verification:", decrypted)
