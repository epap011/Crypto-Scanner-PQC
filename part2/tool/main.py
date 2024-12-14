from CryptoScannerGui import CryptoScannerGUI
from DatabaseManager import DatabaseManager
from CryptoAnalyzer import CryptoAnalyzer
import tkinter as tk

# Define cryptographic patterns
patterns = {
    # Symmetric Ciphers
    'DES': r'\bDES\b',
    '3DES': r'\b3DES\b',
    '3DES_1Key': r'\b3DES\b.*?key=(1)',  # Example pattern for 1-key
    '3DES_2Keys': r'\b3DES\b.*?key=(2)',  # Example pattern for 2-keys
    '3DES_3Keys': r'\b3DES\b.*?key=(3)',  # Example pattern for 3-keys
    'AES': r'\bAES\b.*?mode=([A-Z]+)',
    'AES-128': r'\bAES\b.*?key_size=(128)',
    'AES-192': r'\bAES\b.*?key_size=(192)',
    'AES-256': r'\bAES\b.*?key_size=(256)',  # Explicitly mark AES-256 as secure
    'Blowfish': r'\bBlowfish\b.*?key_size=(\d+)',  # New pattern for Blowfish
    'RC4': r'\bRC4\b',  # New pattern for RC4

    # Asymmetric Ciphers
    'RSA': r'\bRSA\b.*?\((.*?)\)',
    'RSA_NoPadding': r'\bRSA\b.*?padding=None',
    'ECC': r'\bEllipticCurve\b|\bECC\b',
    'ECDH': r'\bECDH\b',
    'ECDSA': r'\bECDSA\b',
    'Diffie-Hellman': r'\bDH\b|\bDiffieHellman\b',
    'DH_WeakParams': r'\bDH\b.*?modulus_size=(\d+)|generator=(1|p-1)',  # New pattern for weak DH parameters

    # Hash Functions
    'MD5': r'\bMD5\b',
    'SHA1': r'\bSHA-1\b',
    'SHA-224': r'\bSHA-224\b',  # New pattern for SHA-224
    'SHA-256': r'\bSHA-256\b',
    'Whirlpool': r'\bWhirlpool\b',  # New pattern for Whirlpool

    # Weak Modes
    'ECB_Mode': r'\bAES\b.*?mode=ECB|\bDES\b.*?mode=ECB|\b3DES\b.*?mode=ECB',
    'CBC_Mode': r'\bAES\b.*?mode=CBC|\bDES\b.*?mode=CBC|\b3DES\b.*?mode=CBC',
    'Static_IV': r'IV=(0x[a-fA-F0-9]+)',  # New pattern for static IV detection

    # Deprecated Protocols
    'TLS': r'\bTLSv1\\.\d\b|\bSSLv3\b',
    'SSH': r'\bssh-rsa\b|\bssh-dss\b',
    'IPsec': r'\bIKEv1\b',

    # Other Vulnerabilities
    'Hardcoded Key': r'([a-fA-F0-9]{32,})|([\"\']{5,})',  # Detect long hex or string constants
    'Weak PRNG': r'\brandom\\.(random|randint|choice|shuffle|uniform)\b',
    'Cryptography Library': r'\bfrom\s+cryptography|import\s+cryptography\b',
}

# Define risk assessment rules and suggestions
rules = {
    # Symmetric Ciphers
    'DES': ('Critical', 'DES is insecure; avoid using.', 'Replace with AES-GCM or AES-CCM'),
    '3DES': ('Critical', '3DES is insecure; avoid using.', 'Replace with AES-GCM or AES-CCM'),
    '3DES_1Key': ('Critical', '3DES with 1 key provides no additional security.', 'Replace with AES-GCM or AES-CCM'),
    '3DES_2Keys': ('Critical', '3DES with 2 keys is insecure.', 'Replace with AES-GCM or AES-CCM'),
    '3DES_3Keys': ('Critical', '3DES with 3 keys is deprecated and quantum-vulnerable.', 'Replace with AES-GCM or AES-CCM'),
    'AES-128': ('Medium', 'AES-128 is not quantum-safe.', 'Upgrade to AES-256 for quantum resilience.'),
    'AES-192': ('Medium', 'AES-192 is not quantum-safe.', 'Upgrade to AES-256 for quantum resilience.'),
    'AES-256': ('Low', 'AES-256 is secure against quantum and classical attacks.', 'No action required.'),
    'Blowfish': lambda key_size: (
        ('Critical', f'Blowfish key size {key_size} is too small.', 'Use AES-256 or better.')
        if int(key_size) < 128 else ('Low', 'Blowfish with adequate key size detected.', 'No action required.')
    ),
    'RC4': ('Critical', 'RC4 is insecure; avoid using.', 'Replace with AES-GCM or AES-CCM.'),

    # Asymmetric Ciphers
    'RSA': lambda key_size: (
        ('Critical', 'Invalid or missing RSA key size; verify manually.', 'Replace with Kyber (PQC)')
        if not key_size.isdigit() else
        ('High' if int(key_size) >= 2048 else 'Critical', f'RSA key size {key_size} is quantum-vulnerable; must migrate to PQC.', 'Use Kyber or hybrid schemes.')
    ),
    'RSA_NoPadding': ('Critical', 'RSA without padding is vulnerable to padding oracle attacks.', 'Use OAEP or PSS padding.'),
    'ECC': ('High', 'ECC is quantum-vulnerable; transition to PQC.', 'Replace with NTRU or hybrid schemes.'),
    'ECDH': ('High', 'ECDH is quantum-vulnerable; transition to PQC.', 'Use hybrid Diffie-Hellman or Kyber.'),
    'ECDSA': ('High', 'ECDSA is quantum-vulnerable; transition to PQC.', 'Replace with Dilithium (PQC).'),
    'DH_WeakParams': ('Critical', 'Diffie-Hellman weak parameters detected.', 'Use a secure modulus (>= 2048 bits) and generator.'),

    # Hash Functions
    'MD5': ('Critical', 'MD5 is outdated; replace with SHA-256 or better.', 'Replace with SHA-256 or SHA-3'),
    'SHA1': ('Critical', 'SHA-1 is outdated; replace with SHA-256 or better.', 'Replace with SHA-256 or SHA-3'),
    'SHA-224': ('High', 'SHA-224 is too small for modern security.', 'Upgrade to SHA-256 or SHA-3.'),
    'SHA-256': ('Medium', 'SHA-256 is quantum-vulnerable.', 'Consider SHA-3 for quantum resilience.'),
    'Whirlpool': ('Medium', 'Whirlpool is secure but uncommon; verify implementation.', 'Ensure proper implementation or replace with SHA-3.'),

    # Weak Modes
    'ECB_Mode': ('Critical', 'ECB mode leaks patterns in plaintext.', 'Switch to GCM or CCM.'),
    'CBC_Mode': ('High', 'CBC mode with static IV is vulnerable.', 'Switch to GCM or CCM.'),
    'Static_IV': ('Critical', 'Static IV detected; this is insecure.', 'Use a randomized IV for each encryption operation.'),

    # Deprecated Protocols
    'TLS': ('Critical', 'Deprecated TLS version detected.', 'Upgrade to TLS 1.3 with PQC support.'),
    'SSH': ('Critical', 'Weak SSH algorithm detected.', 'Use Ed25519 or PQC alternatives.'),
    'IPsec': ('Critical', 'Deprecated IPsec version detected.', 'Use IKEv2 with PQC support.'),

    # Other Vulnerabilities
    'Hardcoded Key': ('Critical', 'Hardcoded cryptographic key detected.', 'Avoid embedding keys directly in code.'),
    'Weak PRNG': ('High', 'Weak PRNG detected; use `secrets` module instead.', 'Replace with `secrets` module.'),
    'Cryptography Library': ('Medium', 'Usage of cryptography library detected. Review its usage for secure practices.', 'Ensure correct key management and secure algorithm selection.'),
}

# Define deprecated APIs
deprecated_apis = {
    'ssl.PROTOCOL_TLSv1': ('Critical', 'Deprecated SSL/TLS protocol detected.', 'Update to TLS 1.2 or 1.3.'),
    'paramiko.DSSKey': ('Critical', 'Deprecated SSH key type detected.', 'Use Ed25519 or RSA with >=2048 bits.')
}

# Initialize components
db_manager = DatabaseManager()
crypto_analyzer = CryptoAnalyzer(patterns, rules, deprecated_apis, mosca_params=(10, 5, 15))

# Start GUI
root = tk.Tk()
app = CryptoScannerGUI(root, crypto_analyzer, db_manager)
root.mainloop()
