#weak_prng.py
import random

# Using a weak PRNG for cryptographic purposes
key = random.randint(1, 1000000)
print("Weak PRNG Key:", key)
