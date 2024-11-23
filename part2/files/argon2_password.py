from argon2 import PasswordHasher

ph = PasswordHasher()
hash = ph.hash("securepassword")
print("Argon2 Hash:", hash)
