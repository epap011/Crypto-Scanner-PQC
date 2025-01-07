#test_weak_key_sizes.py
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# Weak RSA Key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024  # Weak key size
)

# ECDH Key Exchange
ec_key = ec.generate_private_key(
    ec.SECP192R1()  # Non-recommended curve
)
