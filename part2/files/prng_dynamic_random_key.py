#prng_dynamic_random_key.py
import random

# Using PRNG for generating keys dynamically (insecure)
key = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
print("Dynamically Generated Weak Key:", key)
