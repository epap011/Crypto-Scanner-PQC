#no_certificate_validation.py
import ssl
import socket

# Example of missing certificate validation
hostname = 'example.com'
context = ssl._create_unverified_context()  # Insecure: skips certificate validation

with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print("Established insecure connection to:", ssock.getpeercert())
