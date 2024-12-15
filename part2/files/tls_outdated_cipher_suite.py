#tls_outdated_cipher_suite.py
import ssl

# Using an outdated cipher suite in TLS
context = ssl.create_default_context()
context.set_ciphers("DES-CBC3-SHA")  # Weak cipher suite
print("TLS Context with Weak Cipher Suite:", context)
