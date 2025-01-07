#ecc_deprecated_curve.py
from cryptography.hazmat.primitives.asymmetric import ec

# Using a deprecated or insecure curve (non-recommended)
private_key = ec.generate_private_key(ec.SECP192R1())
public_key = private_key.public_key()
print("ECC Public Key with Deprecated Curve:", public_key)
