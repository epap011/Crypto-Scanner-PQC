import bcrypt

password = b"securepassword"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print("bcrypt Hash:", hashed)
