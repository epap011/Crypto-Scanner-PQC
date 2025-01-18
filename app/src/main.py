from gui.base_gui import CryptoScannerApp
from core.analyzer import CryptoAnalyzer
from core.database_manager import DatabaseManager
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


    # Argon2 Weak Parameters
    'Argon2_WeakParams': r'PasswordHasher\(time_cost=(\d+), memory_cost=(\d+), parallelism=(\d+)\)',
    # bcrypt Weak Rounds
    'bcrypt_weak_rounds': r'bcrypt\.gensalt\(rounds=(\d+)\)',
    # Deprecated ECC Curves
    'ECC_DeprecatedCurve': r'SECP(?:112|128|160|192|224)R1',
    # Hardcoded Usernames
    'Hardcoded_Credentials': r'USERNAME\s*=\s*[\'\"](.*?)[\'\"]',
    # Reuse of Key Material in KDFs
    'KeyReuse_KDF': r'HKDF\(.*?\.derive\((.*?)\)',
    # Missing Salt in Password Hashing
    'PasswordHash_NoSalt': r'hashlib\.\w+\(.*?password\)',
    # Weak PRNG for Key Generation
    'Weak_PRNG_KeyGen': r'random\.\w+\(',
    # Missing GCM Tag Verification
    'GCM_NoTagCheck': r'AES\.new\(.*?MODE_GCM.*?\).decrypt\(',
    # Weak Blowfish Key
    'Blowfish_WeakKey': r'Blowfish\.new\((.*?)\)',
    # Weak DH Generator
    'DH_WeakGenerator': r'generate_parameters\(generator=(\d+)',

    'AES_ECB_Mode': r'\bAES\.new\(.*?,\s*AES\.MODE_ECB\)',
    'AES_GCM_NoTagCheck': r'AES\.new\(.*?,\s*AES\.MODE_GCM.*?\)\.decrypt\(.*?\)',
    'Argon2_WeakParams': r'PasswordHasher\(time_cost=(\d+), memory_cost=(\d+), parallelism=(\d+)\)',
    'Argon2_DefaultParams': r'PasswordHasher\(\)',
    'bcrypt_default_rounds': r'bcrypt\.gensalt\(.*?\)',
    'bcrypt_weak_rounds': r'bcrypt\.gensalt\(rounds=(\d+)\)',
    'Blowfish_ShortKey': r'Blowfish\.new\(.*?,\s*key=(b".{1,15}"|b".{,15}")',

    # Missing GCM tag verification
    'GCM_MissingTagCheck': r'AES\.new\(.*?,\s*AES\.MODE_GCM.*?\)\.decrypt\(',
    # Default Argon2 parameters
    'Argon2_DefaultParams': r'PasswordHasher\(\)',
    # Default bcrypt rounds
    'bcrypt_default_rounds': r'bcrypt\.gensalt\(.*?\)',
    # No certificate validation
    'NoCertValidation_SSL': r'_create_unverified_context\(',
    'NoCertValidation_Requests': r'requests\.get\(.*?,\s*verify=False',
    'NoCertValidation_Urllib': r'ssl\.create_default_context\(.*?\)',
    # Weak cipher suites
    'TLS_WeakCipherSuite': r'set_ciphers\(.*?(DES|3DES|RC4)',
    # Insufficient PBKDF2 iterations
    'PBKDF2_WeakIterations': r'pbkdf2_hmac\(.*?,.*?,.*?,\s*(\d+)',
    # Hardcoded RSA private keys (PEM format)
    'Hardcoded_RSA_PrivateKey': r'-----BEGIN RSA PRIVATE KEY-----',
    # Hardcoded symmetric keys
    'Hardcoded_SymmetricKey': r'["\']([a-fA-F0-9]{32,})["\']',
    # Insecure protocol references
    'InsecureProtocol_Strings': r'TLSv1\.0|SSLv3|IKEv1',
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



    # Weak Argon2 Parameters
    'Argon2_WeakParams': lambda params: (
        ('Critical', f'Weak Argon2 parameters: {params}', 'Use time_cost >= 2, memory_cost >= 65536, and parallelism >= 2.')
        if int(params['time_cost']) < 2 or int(params['memory_cost']) < 65536 or int(params['parallelism']) < 2
        else ('Low', 'Argon2 parameters are secure.', 'No action required.')
    ),
    # Weak bcrypt Rounds
    'bcrypt_weak_rounds': lambda rounds: (
        ('Critical', f'Weak bcrypt rounds: {rounds}', 'Use bcrypt.gensalt(rounds=12) or higher.')
        if int(rounds) < 12 else ('Low', 'bcrypt rounds are sufficient.', 'No action required.')
    ),
    # Deprecated ECC Curves
    'ECC_DeprecatedCurve': ('Critical', 'Deprecated ECC curve detected.', 'Use curves like SECP256R1, SECP384R1, or X25519.'),
    # Hardcoded Usernames
    'Hardcoded_Credentials': ('Critical', 'Hardcoded credentials detected.', 'Avoid embedding usernames or passwords in code. Use environment variables.'),
    # Key Material Reuse in KDFs
    'KeyReuse_KDF': ('Critical', 'Key material reused in KDF derivation.', 'Avoid reusing key material. Use unique salts and diversify derivation inputs.'),
    # Missing Salt in Password Hashing
    'PasswordHash_NoSalt': ('Critical', 'Password hashing without salt.', 'Use a unique, random salt for each password.'),
    # Weak PRNG for Key Generation
    'Weak_PRNG_KeyGen': ('Critical', 'Weak PRNG detected for key generation.', 'Use the `secrets` module or a cryptographically secure PRNG.'),
    # Missing GCM Tag Verification
    'GCM_NoTagCheck': ('Critical', 'Missing GCM authentication tag verification.', 'Ensure authentication tag is verified during decryption.'),
    # Weak Blowfish Keys
    'Blowfish_WeakKey': ('Critical', 'Weak Blowfish key detected.', 'Use a Blowfish key of at least 128 bits or switch to AES.'),
    # Weak DH Generator
    'DH_WeakGenerator': ('Critical', 'Weak Diffie-Hellman generator detected.', 'Use generator=2 or higher. Avoid using 1 or (p-1).'),

    'AES_ECB_Mode': ('Critical', 'ECB mode leaks plaintext patterns.', 'Switch to AES-GCM or AES-CCM.'),
    'AES_GCM_NoTagCheck': ('Critical', 'Missing GCM authentication tag verification.', 'Ensure authentication tag is verified.'),
    'Blowfish_ShortKey': ('Critical', 'Blowfish key is too short (less than 128 bits).', 'Use keys >= 128 bits or switch to AES-256.'),

    'GCM_MissingTagCheck': ('Critical', 'Missing GCM authentication tag verification.', 'Ensure authentication tag is verified.'),
    'Argon2_DefaultParams': ('Medium', 'Argon2 is used with default parameters.', 'Specify secure parameters: time_cost >= 2, memory_cost >= 65536, parallelism >= 2.'),
    'bcrypt_default_rounds': ('Medium', 'bcrypt is used with default rounds.', 'Ensure rounds >= 12 for adequate security.'),
    'NoCertValidation_SSL': ('Critical', 'SSL context with no certificate validation detected.', 'Use a proper SSL context that validates certificates.'),
    'NoCertValidation_Requests': ('Critical', 'Insecure requests.get call with SSL validation disabled.', 'Enable SSL validation by setting verify=True.'),
    'NoCertValidation_Urllib': ('Critical', 'Insecure urllib call with SSL validation disabled.', 'Use a proper SSL context that validates certificates.'),
    'TLS_WeakCipherSuite': ('Critical', 'Weak TLS cipher suite detected.', 'Use secure cipher suites like AES-GCM.'),
    'PBKDF2_WeakIterations': lambda iterations: (
        ('Critical', f'Insufficient PBKDF2 iterations: {iterations}', 'Use at least 100,000 iterations.')
        if int(iterations) < 100000 else ('Low', 'PBKDF2 iterations are sufficient.', 'No action required.')
    ),
    'Hardcoded_RSA_PrivateKey': ('Critical', 'Hardcoded RSA private key detected.', 'Avoid embedding private keys in code. Use secure storage.'),
    'Hardcoded_SymmetricKey': ('Critical', 'Hardcoded symmetric cryptographic key detected.', 'Avoid embedding keys directly in code. Use environment variables or secure storage.'),
    'InsecureProtocol_Strings': ('Critical', 'Insecure protocol reference detected.', 'Replace with secure protocols like TLS 1.3.'),
}

# Define deprecated APIs
deprecated_apis = {
    'ssl.PROTOCOL_TLSv1': ('Critical', 'Deprecated SSL/TLS protocol detected.', 'Update to TLS 1.2 or 1.3.'),
    'paramiko.DSSKey': ('Critical', 'Deprecated SSH key type detected.', 'Use Ed25519 or RSA with >=2048 bits.')
}

# Initialize components
db_manager      = DatabaseManager()
crypto_analyzer = CryptoAnalyzer(patterns, rules, deprecated_apis, mosca_params=(10, 5, 15))

# Start GUI
root = tk.Tk()
app = CryptoScannerApp(root, crypto_analyzer, db_manager)
root.mainloop()