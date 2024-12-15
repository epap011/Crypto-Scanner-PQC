#dh_vulnerable_params.py
from cryptography.hazmat.primitives.asymmetric import dh

# Using weak parameters for Diffie-Hellman
parameters = dh.generate_parameters(generator=1, key_size=1024)  # Weak generator and key size
private_key = parameters.generate_private_key()
print("Weak Diffie-Hellman Private Key:", private_key)
