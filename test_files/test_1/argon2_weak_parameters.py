#argon2_weak_parameters.py
from argon2 import PasswordHasher

# Insecure: Using weak parameters (e.g., default time_cost, memory_cost)
ph = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
hash = ph.hash("securepassword")
print("Argon2 Hash with Weak Parameters:", hash)