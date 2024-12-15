#md5_collision_example.py
import hashlib

# Two different inputs that produce the same MD5 hash (collision example)
data1 = b"Example1"
data2 = b"Example2"
hash1 = hashlib.md5(data1).hexdigest()
hash2 = hashlib.md5(data2).hexdigest()

print("Hash 1:", hash1)
print("Hash 2:", hash2)
print("Collision Detected:", hash1 == hash2)
