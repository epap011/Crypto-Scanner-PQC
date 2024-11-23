from Crypto.Cipher import AES

key = b'16bytekey1234567'
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(b'16byteblock12345')
print("AES ECB Encrypted:", encrypted)
