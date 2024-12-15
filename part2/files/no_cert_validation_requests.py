#no_cert_validation_requests.py
import requests

# Insecure: SSL certificate validation disabled
response = requests.get('https://example.com', verify=False)
print("Insecure Request Response:", response.status_code)
