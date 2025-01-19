#insecure_random_key.py
import random

# Using random for key generation (not cryptographically secure)
key = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
print("Insecure Random Key:", key)
