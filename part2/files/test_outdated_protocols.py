import ssl
import paramiko

# Deprecated SSL/TLS protocol
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # Deprecated protocol version

# Deprecated SSH key type
key = paramiko.DSSKey()  # Deprecated SSH DSA key
