#misuse_of_crypto_library.py
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

key_material = b"key_material"

# Incorrectly reusing the same key material without proper diversification
hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=None, backend=default_backend())
key1 = hkdf.derive(key_material)
key2 = hkdf.derive(key_material)  # Reuse of the same key material
print("Derived Keys:", key1, key2)
