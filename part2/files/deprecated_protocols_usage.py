#deprecated_protocols_usage.py
import ssl

# Deprecated protocol usage
context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # SSLv3 is insecure and deprecated
print("SSL Context with SSLv3 created:", context)
