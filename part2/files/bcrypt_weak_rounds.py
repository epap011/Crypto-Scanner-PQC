import bcrypt

password = b"securepassword"
# Insecure: Very low cost factor (rounds)
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=4))
print("bcrypt Hash with Weak Rounds:", hashed)
