#hybrid_crypto_invalid_config.py
from cryptography.hazmat.primitives.asymmetric import rsa
from pqcrypto.kem.kyber import generate_keypair, encapsulate

# Incorrect hybrid cryptography setup
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
kyber_pubkey, kyber_privkey = generate_keypair()

# Insecure: Failing to properly combine RSA and Kyber outputs
rsa_ciphertext = rsa_key.private_numbers().d
kyber_ciphertext, shared_secret = encapsulate(kyber_pubkey)

print("Insecure Hybrid Setup Outputs:", rsa_ciphertext, kyber_ciphertext)
