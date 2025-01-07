# Part 2 Report: Cryptographic Inventory and Risk Assessment

## Introduction

This report documents the implementation and results of **Part 2** of the project, focusing on developing a **Cryptographic Inventory Tool** capable of detecting, prioritizing, and managing vulnerabilities in cryptographic primitives. We have extended our implementation to fully cover the required features and bonus tasks as described in the project guidelines.

Building upon concepts outlined in **Part 1**, the project leverages principles of cryptographic agility and post-quantum cryptography (PQC) readiness. Our approach employs both **pattern-based analysis** and **semantic inspection** for identifying vulnerabilities, with Python as the target programming language to ensure thorough detection.

## Features

### Comprehensive Vulnerability Detection

The tool detects a range of vulnerabilities in Python code by combining two methods:
- **Pattern Matching**: Quickly identifies cryptographic issues using predefined expressions.
- **Semantic Inspection**: Provides deeper analysis, capturing vulnerabilities involving parameters, configurations, or logic spread across multiple lines.

This dual-layered approach ensures robust coverage of potential weaknesses, balancing speed and accuracy in detection.

### Risk Prioritization

The tool categorizes vulnerabilities by severity:
- **Critical**: Requires immediate attention.
- **High**: Significant but less urgent.
- **Medium**: Requires action in the medium term.
- **Low**: No immediate action required.

Risk levels are dynamically assigned based on vulnerability details, and findings are flagged as **quantum-vulnerable** when applicable. To aid decision-making, results can be ordered by severity and visualized with colored tags for each risk level.

### User Interface (GUI)

The GUI provides an intuitive platform for:
- Selecting directories for scanning.
- Viewing and filtering results by severity, issue type, and file name.
- Searching findings by file name or issue details.
- Exporting findings to CSV for reporting or further analysis.
- Managing cases, including creating, loading, and deleting investigations.

### Bonus Features

#### 1. Expanded Vulnerability Detection
Additional patterns and semantic rules identify issues such as deprecated ECC curves, weak bcrypt parameters, and hardcoded private keys.

#### 2. Case Management
Users can create and manage specific cases, with findings stored under unique names for future review or updates.

#### 3. Database Management
Functionalities include:
- Exporting findings to CSV.
- Importing data from previously exported files.
- Clearing the database for fresh investigations.

#### 4. Enhanced Visualization
The GUI includes statistical breakdowns of vulnerabilities by severity, accompanied by bar charts for improved analysis.

## Design and Implementation

### Vulnerability Detection

he tool employs two complementary methods:
- **Pattern Matching**: Identifies cryptographic issues through predefined expressions, such as locating the use of AES-ECB or static IVs. For example:
  - **AES-ECB Mode**: `\bAES\.new\(.*?,\s*AES\.MODE_ECB\)`
  - **Static IVs**: `IV=(0x[a-fA-F0-9]+)`
  
  These patterns ensure rapid detection of vulnerabilities in languages where AST parsing is unavailable.

- **Semantic Inspection**: Analyzes code structures using Abstract Syntax Trees (AST) to uncover issues like insecure parameter configurations, missing authentication tag verifications, and hardcoded keys. For example:
  ```python
  cipher = AES.new(key, AES.MODE_GCM)
  data = cipher.decrypt(encrypted_data)  # Missing tag verification detected
  ```
  This approach adds depth and precision, complementing Regex-based scanning.

### Cryptographic Inventory Tool

The tool was developed in **Python**, leveraging its extensive library support and suitability for rapid prototyping. It is designed with modularity and clean code principles to ensure maintainability, extensibility, and ease of collaboration.

Key components and libraries include:
- **`tkinter`**: Provides an intuitive graphical user interface for tasks such as selecting directories, viewing results, and managing cases.
- **`re`**: Facilitates pattern-based matching to quickly identify cryptographic vulnerabilities in source code.
- **`ast`**: Enables semantic analysis of Python code, uncovering vulnerabilities that may not be detected through simple pattern recognition.
- **`sqlite3`**: Ensures persistent and lightweight database management for findings, supporting features like case management, data import/export, and summary statistics.

The implementation emphasizes a clear separation of concerns:
- **`CryptoAnalyzer`**: Combines regex-based and AST-based analysis to detect vulnerabilities with precision and depth.
- **`DatabaseManager`**: Handles interactions with the SQLite database, providing storage and retrieval mechanisms for findings, as well as exporting capabilities.
- **`CryptoScannerGUI`**: Acts as the interface layer, allowing users to interact with the tool easily, manage cases, and visualize findings.

### Risk Prioritization with Mosca’s Inequality

To assess the urgency of transitioning from vulnerable cryptographic primitives, the tool integrates **Mosca’s Inequality**:

$X + Y \geq Z$


Where:
- **X**: Time required to replace cryptography.
- **Y**: Useful lifetime of sensitive data.
- **Z**: Time until a quantum computer can break current cryptographic standards.

This framework is applied to findings involving quantum-vulnerable primitives such as RSA and ECC. For such primitives, the tool flags vulnerabilities as **Mosca Urgent** when $ X + Y \geq Z $, prompting immediate attention. This prioritization ensures that the most critical vulnerabilities, especially those posing quantum threats, are addressed first.

The combination of a robust framework and a risk assessment mechanism like Mosca’s Inequality equips the tool to effectively manage cryptographic agility challenges and prepare systems for a post-quantum era.

## Vulnerabilities Detected by Cryptographic Scanner

The **Cryptographic Scanner** is designed to identify a wide array of cryptographic vulnerabilities, ranging from outdated algorithms to insecure implementations. This section provides a detailed explanation of the vulnerabilities detected by the scanner.

### 1. Symmetric Ciphers

#### Data Encryption Standard (DES)
- **Severity**: Critical  
- **Issue**: DES is an outdated symmetric cipher with a 56-bit key, vulnerable to brute-force attacks.  
- **Recommendation**: Replace DES with AES-GCM or AES-CCM for secure encryption.  

#### Triple DES (3DES)
- **Severity**: Critical  
- **Issue**: 3DES is insecure and vulnerable to brute-force attacks. Variants with fewer than three independent keys are particularly weak.  
  - **3DES with 1 Key**: Equivalent to DES.  
  - **3DES with 2 Keys**: Provides only 80-bit security, which is inadequate.  
  - **3DES with 3 Keys**: Deprecated and quantum-vulnerable.  
- **Recommendation**: Replace with AES-GCM or AES-CCM.

#### AES with Insecure Parameters
- **AES-128/192**: Medium severity due to quantum vulnerability.  
- **AES-ECB Mode**: Critical severity as ECB leaks plaintext patterns.  
- **Static IVs in AES-CBC Mode**: Critical severity due to IV reuse leading to predictable ciphertexts.  
- **Recommendation**: Use AES-256 in GCM or CCM mode with randomized IVs.

#### Static IV Detection in Assignments or Concatenations
- **Severity**: Critical  
- **Issue**: Reuse of static IVs compromises ciphertext security.  
- **Recommendation**: Always use a randomized IV for each encryption operation.

#### Blowfish
- **Severity**: Critical (key size < 128 bits), Low (key size ≥ 128 bits).  
- **Issue**: Blowfish is outdated; short keys are especially insecure.  
- **Recommendation**: Use AES-256 instead.

#### RC4
- **Severity**: Critical  
- **Issue**: RC4 is insecure due to biases in its output, leading to plaintext recovery.  
- **Recommendation**: Avoid using RC4 altogether.

---

### 2. Asymmetric Ciphers

#### RSA
- **Severity**: High to Critical  
- **Issue**: Key sizes < 2048 bits are quantum-vulnerable and insecure. RSA without padding is also vulnerable to attacks.  
- **Recommendation**: Use RSA with a key size ≥ 3072 bits and OAEP or PSS padding. Transition to post-quantum cryptography (e.g., Kyber).

#### Elliptic Curve Cryptography (ECC)
- **Severity**: High  
- **Issue**: ECC is quantum-vulnerable. Deprecated curves (e.g., SECP112R1) are particularly insecure.  
- **Recommendation**: Use modern curves (e.g., SECP256R1) or transition to post-quantum alternatives.

#### Deprecated ECC Curves
- **Severity**: Critical  
- **Issue**: Deprecated ECC curves (e.g., SECP112R1) are insecure and should be avoided.  
- **Recommendation**: Use modern curves like SECP256R1 or X25519.

#### Diffie-Hellman (DH)
- **Severity**: Critical  
- **Issue**: Weak parameters such as small modulus sizes or generators can be exploited.  
- **Recommendation**: Use a secure modulus (≥ 2048 bits) and generator values ≥ 2.

#### Weak Diffie-Hellman Generator
- **Severity**: Critical  
- **Issue**: Generator values of 1 or \( p-1 \) are insecure and weaken the key exchange.  
- **Recommendation**: Use a secure generator value (e.g., 2).

---

### 3. Hash Functions

#### MD5
- **Severity**: Critical  
- **Issue**: MD5 is vulnerable to collisions and should not be used for security purposes.  
- **Recommendation**: Replace with SHA-256 or SHA-3.

#### SHA-1
- **Severity**: Critical  
- **Issue**: SHA-1 is vulnerable to collision attacks and is no longer secure.  
- **Recommendation**: Replace with SHA-256 or SHA-3.

#### Whirlpool
- **Severity**: Medium  
- **Issue**: Whirlpool is secure but uncommon, potentially leading to interoperability issues.  
- **Recommendation**: Use SHA-3 for wider support.

---

### 4. Weak Cryptographic Modes

#### ECB Mode
- **Severity**: Critical  
- **Issue**: ECB mode leaks patterns in plaintext, compromising confidentiality.  
- **Recommendation**: Use GCM or CCM instead.

#### CBC Mode with Static IV
- **Severity**: Critical  
- **Issue**: Reusing IVs in CBC mode enables ciphertext manipulation and pattern discovery.  
- **Recommendation**: Use GCM or CCM with randomized IVs.

#### Missing GCM Tag Verification
- **Severity**: Critical  
- **Issue**: Failing to verify the authentication tag in GCM mode exposes the ciphertext to tampering.  
- **Recommendation**: Always verify authentication tags.

#### AES GCM Without Authentication Tag Verification
- **Severity**: Critical  
- **Issue**: GCM mode used without verifying the authentication tag enables tampering.  
- **Recommendation**: Always verify the authentication tag during decryption.

---

### 5. Deprecated Protocols

#### SSL/TLS
- **Severity**: Critical  
- **Issue**: Deprecated versions (e.g., SSLv3, TLSv1.0) are insecure.  
- **Recommendation**: Upgrade to TLS 1.3 with secure cipher suites.

#### TLS Weak Cipher Suite
- **Severity**: Critical  
- **Issue**: Weak cipher suites like DES, 3DES, or RC4 compromise security in TLS communication.  
- **Recommendation**: Use AES-GCM or ChaCha20 cipher suites.

#### SSH
- **Severity**: Critical  
- **Issue**: Deprecated algorithms like `ssh-rsa` and `ssh-dss` are insecure.  
- **Recommendation**: Use Ed25519 or modern RSA keys with ≥ 2048 bits.

#### IPsec
- **Severity**: Critical  
- **Issue**: IKEv1 is deprecated and vulnerable to multiple attacks.  
- **Recommendation**: Use IKEv2 with secure configurations.

#### Deprecated Protocol References
- **Severity**: Critical  
- **Issue**: Strings referencing insecure protocols like `TLSv1.0`, `SSLv3`, or `IKEv1` indicate potential weaknesses.  
- **Recommendation**: Update to modern protocols such as TLS 1.3.

---

### 6. Other Vulnerabilities

#### Missing Certificate Validation
- **Severity**: Critical  
- **Issue**: SSL/TLS calls without certificate validation compromise security.  
- **Recommendation**: Enable certificate validation to prevent man-in-the-middle attacks.

#### Hardcoded Keys
- **Severity**: Critical  
- **Issue**: Embedding keys directly in code compromises security.  
- **Recommendation**: Use environment variables or secure key management solutions.

#### Hardcoded Usernames
- **Severity**: Critical  
- **Issue**: Hardcoded usernames in code increase the risk of exposure and compromise.  
- **Recommendation**: Use environment variables or secure configuration files for user credentials.

#### Hardcoded RSA Private Key
- **Severity**: Critical  
- **Issue**: PEM-encoded RSA private keys should not be embedded in code.  
- **Recommendation**: Use secure key management solutions.

#### Weak PRNGs
- **Severity**: High  
- **Issue**: Using weak PRNGs (e.g., `random.randint`) for cryptographic purposes is insecure.  
- **Recommendation**: Use the `secrets` module or `os.urandom`.

#### Weak Argon2 Parameters
- **Severity**: Critical  
- **Issue**: Parameters with low time cost, memory cost, or parallelism weaken password hashing.  
- **Recommendation**: Use time_cost ≥ 2, memory_cost ≥ 65536, and parallelism ≥ 2.

#### Argon2 Default Parameters
- **Severity**: Medium  
- **Issue**: Usage of Argon2 without explicitly specifying parameters defaults to insecure settings.  
- **Recommendation**: Specify secure parameters: time_cost ≥ 2, memory_cost ≥ 65536, parallelism ≥ 2.

#### Weak bcrypt Rounds
- **Severity**: Critical  
- **Issue**: bcrypt with rounds < 12 is computationally weak.  
- **Recommendation**: Use rounds ≥ 12.

#### Deprecated API Usage
- **Severity**: Critical  
- **Issue**: Deprecated APIs (e.g., `ssl.PROTOCOL_TLSv1`) weaken security.  
- **Recommendation**: Replace with modern equivalents like `ssl.PROTOCOL_TLSv1_2`.

#### bcrypt Default Rounds
- **Severity**: Medium  
- **Issue**: bcrypt without specifying rounds defaults to insufficient iterations.  
- **Recommendation**: Specify rounds ≥ 12 for bcrypt.

#### Reuse of Key Material in KDFs
- **Severity**: Critical  
- **Issue**: Reusing key material in KDFs compromises key derivation security.  
- **Recommendation**: Use unique salts and diversify derivation inputs.

#### Missing Salt in Password Hashing
- **Severity**: Critical  
- **Issue**: Password hashing without salt allows for dictionary attacks.  
- **Recommendation**: Always use a unique, random salt.

#### Insufficient PBKDF2 Iterations
- **Severity**: Critical  
- **Issue**: PBKDF2 with fewer than 100,000 iterations is computationally weak.  
- **Recommendation**: Use PBKDF2 with ≥ 100,000 iterations.

#### Key Material Reuse in HKDF
- **Severity**: Critical  
- **Issue**: Reusing the same key material in HKDF derivation compromises security.  
- **Recommendation**: Use unique salts and diversify derivation inputs for each key derivation.

## Conclusion

Our Cryptographic Inventory Tool successfully identifies, categorizes, and prioritizes vulnerabilities in Python code. By combining pattern-based and semantic methods, incorporating risk prioritization, and providing an intuitive GUI, the tool offers a comprehensive solution for managing cryptographic risks. The inclusion of bonus features enhances its utility, making it a robust framework for assessing cryptographic agility.

