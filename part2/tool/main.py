#main.py
from CryptoScannerGui import CryptoScannerGUI
from DatabaseManager import DatabaseManager
from CryptoAnalyzer import CryptoAnalyzer
import tkinter as tk

# Define cryptographic patterns
patterns = {
    'DES'                 : r'\bDES\b',
    '3DES'                : r'\b3DES\b',
    'MD5'                 : r'\bMD5\b',
    'SHA1'                : r'\bSHA-1\b',
    'SHA2_224'            : r'\bSHA-224\b',
    'RSA'                 : r'\bRSA\b.*?\((.*?)\)',
    'DSA'                 : r'\bDSA\b',
    'ECC'                 : r'\bEllipticCurve\b|\bECC\b',
    'ECDH'                : r'\bECDH\b',
    'ECDSA'               : r'\bECDSA\b',
    'AES'                 : r'\bAES\b.*?mode=([A-Z]+)',
    'bcrypt'              : r'\bbcrypt\b',
    'argon2'              : r'\bargon2\b',
    'Diffie-Hellman'      : r'\bDH\b|\bDiffieHellman\b',
    'TLS'                 : r'\bTLSv1\.\d\b|\bSSLv3\b',
    'SSH'                 : r'\bssh-rsa\b|\bssh-dss\b',
    'IPsec'               : r'\bIKEv1\b',
    'Hardcoded Key'       : r'([a-fA-F0-9]{32,})|(["\']{5,})',  # Detect long hex or string constants maybe it could be done better
    'Weak PRNG'           : r'\brandom\.(random|randint|choice|shuffle|uniform)\b',
    'Cryptography Library': r'\bfrom\s+cryptography|import\s+cryptography\b',
    'PyCrypto'            : r'\bfrom\s+Crypto|import\s+Crypto\b',
    'pycryptodome'        : r'\bfrom\s+Cryptodome|import\s+Cryptodome\b',
    'Django Cryptography' : r'\bdjango\.db\.models\.BinaryField\b',
    'Flask-Security'      : r'\bflask_security\.utils\b',
    'FastAPI Cryptography': r'\bfastapi_security\b', 
}

# Define risk assessment rules and suggestions
rules = {
    'DES'                 : ('Critical', 'DES is insecure; avoid using.'                     , 'Replace with AES-GCM or AES-CCM'),
    '3DES'                : ('Critical', '3DES is insecure; avoid using.'                    , 'Replace with AES-GCM or AES-CCM'),
    'MD5'                 : ('Critical', 'MD5 is outdated; replace with SHA-256 or better.'  , 'Replace with SHA-256 or SHA-3'),
    'SHA1'                : ('Critical', 'SHA-1 is outdated; replace with SHA-256 or better.', 'Replace with SHA-256 or SHA-3'),
    'SHA2_224'            : ('Medium'  , 'SHA-224 is deprecated; prefer SHA-256 or better.'  , 'Replace with SHA-256 or SHA-3'),
    'RSA': lambda key_size: ( 
        ('Critical', "Invalid or missing RSA key size; verify manually.", 'Replace with Kyber (PQC)') 
        if not key_size.isdigit() else 
        ('High' if int(key_size) >= 2048 else 'Critical', f"RSA key size {key_size} is quantum-vulnerable; must migrate to PQC.", 'Use Kyber or hybrid schemes.')
    ),
    'ECC'                 : ('High', 'ECC is quantum-vulnerable; transition to PQC.'  , 'Replace with NTRU or hybrid schemes.'),
    'ECDH'                : ('High', 'ECDH is quantum-vulnerable; transition to PQC.' , 'Use hybrid Diffie-Hellman or Kyber.'),
    'ECDSA'               : ('High', 'ECDSA is quantum-vulnerable; transition to PQC.', 'Replace with Dilithium (PQC).'),
    'AES'  : lambda mode: (
        ('Medium' if mode in ['ECB', 'CBC'] else 'Low', f"AES mode {mode} is less secure; prefer GCM or CCM.", 'Switch to GCM or CCM.')
    ),
    'bcrypt'              : ('Low'     , 'bcrypt is secure but computationally expensive.'  , 'Consider Argon2 for new systems.'),
    'argon2'              : ('Low'     , 'argon2 is currently secure and recommended.'      , 'No action needed.'),
    'Diffie-Hellman'      : ('High'    , 'Weak DH parameters are quantum-vulnerable; ensure strong group sizes.', 'Use hybrid Diffie-Hellman or Kyber.'),
    'TLS'                 : ('Critical', 'Deprecated TLS version detected.'                 , 'Upgrade to TLS 1.3 with PQC support.'),
    'SSH'                 : ('Critical', 'Weak SSH algorithm detected.'                     , 'Use Ed25519 or PQC alternatives.'),
    'IPsec'               : ('Critical', 'Deprecated IPsec version detected.'               , 'Use IKEv2 with PQC support.'),
    'Hardcoded Key'       : ('Critical', 'Hardcoded cryptographic key detected.'            , 'Avoid embedding keys directly in code.'),
    'Weak PRNG'           : ('High'    , 'Weak PRNG detected; use `secrets` module instead.', 'Replace with `secrets` module.'),
    'Cryptography Library': ('Medium'  , 'Usage of cryptography library detected. Review its usage for secure practices.', 'Ensure correct key management and secure algorithm selection.'),
    'PyCrypto'            : ('Critical', 'PyCrypto is outdated and insecure.'               , 'Replace with `pycryptodome` or other secure libraries.'),
    'pycryptodome'        : ('Medium'  , 'pycryptodome detected. Ensure secure practices.'  , 'Verify secure configurations and key management.'),
    'Django Cryptography' : ('Medium'  , 'Django BinaryField might store sensitive data.'   , 'Use encrypted fields or dedicated cryptographic tools.'),
    'Flask-Security'      : ('Medium'  , 'Flask-Security cryptographic utility detected.'   , 'Review for weak cryptographic implementations or configurations.'),
    'FastAPI Cryptography': ('Medium'  , 'FastAPI cryptographic utility detected.'          , 'Ensure secure configurations and parameter usage.')
}

# Define deprecated APIs
deprecated_apis = {
    'ssl.PROTOCOL_TLSv1': ('Critical', 'Deprecated SSL/TLS protocol detected.', 'Update to TLS 1.2 or 1.3.'),
    'paramiko.DSSKey'   : ('Critical', 'Deprecated SSH key type detected.', 'Use Ed25519 or RSA with >=2048 bits.')
}

# Initialize components
db_manager = DatabaseManager()
crypto_analyzer = CryptoAnalyzer(patterns, rules, deprecated_apis, mosca_params=(10, 5, 15))

# Start GUI
root = tk.Tk()
app  = CryptoScannerGUI(root, crypto_analyzer, db_manager)
root.mainloop()
