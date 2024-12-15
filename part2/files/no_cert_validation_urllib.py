#no_cert_validation_urllib.py
import urllib.request
import ssl

# Insecure: SSL certificate validation disabled
context = ssl._create_unverified_context()
response = urllib.request.urlopen('https://example.com', context=context)
print("Insecure URL Response:", response.status)
