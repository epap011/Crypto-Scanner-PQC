from cryptography.hazmat.primitives.asymmetric import rsa
from pqcrypto.kem.kyber import generate_keypair, encapsulate

# Hybrid RSA and Kyber
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048  # Secure RSA key size
)

# Kyber Key Encapsulation
kyber_pubkey, kyber_privkey = generate_keypair()
shared_secret, encapsulation = encapsulate(kyber_pubkey)
