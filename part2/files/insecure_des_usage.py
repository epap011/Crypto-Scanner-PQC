from Crypto.Cipher import DES

key = b'8bytekey'
cipher = DES.new(key, DES.MODE_ECB)
encrypted = cipher.encrypt(b'secret12')
