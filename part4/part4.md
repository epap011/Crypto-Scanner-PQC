# Part 4 Report: Crypto Agility Simulator Development

## Introduction

This report documents the implementation and results of **Part 4** of the project, focusing on the development of a **Crypto Agility Simulator**. Building upon the cryptographic inventory tool from **Part 2**, this simulator demonstrates cryptographic agility by identifying vulnerabilities, proposing and applying fixes, and simulating transitions between cryptographic primitives. It also supports user interaction for manual fixes, comparisons, and reversion, ensuring flexibility and compliance with modern cryptographic standards.

## Features and Enhancements

### Core Simulator Functionality

The Crypto Agility Simulator provides the following advanced functionalities:

1. **Fix Status Management**
   - A dedicated status column indicates whether a vulnerability has been fixed. This provides a clear overview of remediation progress.
   - Statuses include:
     - **Not Fixed**: Default for newly identified vulnerabilities.
     - **Fixed**: Updated after a successful fix is applied.

2. **Proposed Fix Comparisons**
   - Users can view side-by-side comparisons of vulnerable code and proposed fixes before applying changes.
   - This feature ensures transparency and allows users to verify the validity and suitability of fixes.
   - Fix previews use Abstract Syntax Tree (AST) transformations to ensure syntactic and semantic correctness.

3. **Reversion Capability**
   - The simulator includes a **Revert** button that allows users to restore vulnerable files to their original state.
   - This feature provides a safety net, allowing users to undo changes if a fix introduces issues or incompatibilities.

4. **Dynamic Fix Selection**
   - For each vulnerability, a dropdown menu enables users to select a preferred fix from multiple options.
   - Fixes are tailored to the identified cryptographic primitive, ensuring compatibility and compliance with best practices.
   - Example: For AES vulnerabilities, users can choose between fixes involving different modes of operation or key lengths.

### Enhanced Simulation

1. **Automated Fix Application**
   - The simulator can automatically apply fixes to vulnerabilities with clear, deterministic solutions, such as replacing AES-ECB with AES-GCM.
   - Automation ensures that critical issues are addressed promptly while maintaining code functionality.

2. **Manual Fix Suggestions**
   - For vulnerabilities requiring human intervention (e.g., logic changes), the simulator provides detailed guidance but defers changes to the user.
   - These issues are flagged in the status column as **Manual Intervention Required**.

3. **Compliance Monitoring**
   - The simulator checks fixes for compliance with standards such as **NIST SP 800-57** and **NIST SP 800-131A**.
   - This ensures that proposed changes align with recognized guidelines for cryptographic strength and security.

### User Interface (GUI) Additions

The GUI extends the features introduced in Part 2 with additional enhancements:

1. **Fix Management Panel**
   - Displays vulnerable files alongside the status, fix options, and details of the vulnerability.
   - Double-clicking a file opens a modal window for detailed inspection and fixing.

2. **Interactive Fix Modal**
   - The modal includes:
     - **Original Code Display**: Shows the existing vulnerable code.
     - **Updated Code Preview**: Displays the modified code reflecting the selected fix before it is applied. This allows users to understand what changes will be made and ensures transparency in the remediation process.
     - **Dropdown for Fix Selection**: Enables users to choose between multiple proposed fixes tailored to the identified vulnerability.
     - **Buttons for Action**:
     - **Save Changes**: Applies the selected fix and updates the status to "Fixed".
     - **Revert Changes**: Restores the original code if the applied fix needs to be undone.
     - **Close**: Exits the modal without making changes.

3. **Statistics and Insights**
   - The GUI aggregates and displays statistics on vulnerabilities, including:
     - Number of issues fixed automatically.
     - Files requiring manual intervention.
     - Breakdown of vulnerabilities by severity (Critical, High, Medium, Low).

4. **Case Management**
   - The simulator integrates seamlessly with the case management features from Part 2, enabling users to:
     - Load previous cases to continue remediation.
     - Export findings and fixes for reporting.

## Vulnerabilities Addressed by Crypto Agility Simulator

### 1. Symmetric Cipher Vulnerabilities

#### Data Encryption Standard (DES) and Triple DES (3DES)
- **Issue**: DES and 3DES are outdated symmetric ciphers prone to brute-force attacks.  
  - **Fix**: Replace DES and 3DES with AES-GCM for secure encryption.

#### AES with Insecure Modes
- **Issue**: Modes such as AES-ECB leak plaintext patterns. Static IVs in AES-CBC compromise ciphertext security.  
  - **Fix**: Replace AES-ECB with AES-GCM or AES-CCM. Replace static IVs with randomized IVs to ensure unpredictability.

#### Weak Cipher Modes
- **Issue**: ECB mode and static IVs expose plaintext patterns and enable chosen-plaintext attacks.  
  - **Fix**: Replace these modes with AES-GCM or AES-CCM and enforce randomized IVs.

#### GCM Tag Verification
- **Issue**: Skipping authentication tag verification in AES-GCM compromises the integrity of ciphertext.  
  - **Fix**: Add explicit GCM tag verification in decryption routines.

---

### 2. Asymmetric Cipher Vulnerabilities

#### RSA
- **Issue**: Key sizes below 2048 bits are insecure, and improper padding schemes lead to vulnerabilities.  
  - **Fix**: Upgrade RSA keys to 3072 bits and use OAEP or PSS padding schemes.

#### Diffie-Hellman (DH)
- **Issue**: Weak parameters (e.g., small modulus sizes) and quantum vulnerabilities compromise security.  
  - **Fix**: Upgrade DH to RSA-3072 or transition to post-quantum cryptography (e.g., Kyber).

---

### 3. Hash Function Vulnerabilities

#### MD5, SHA-1, and SHA-224
- **Issue**: These hashing algorithms are deprecated due to collision vulnerabilities.  
  - **Fix**: Replace MD5, SHA-1, and SHA-224 with SHA-256.

---

### 4. Password Hashing Vulnerabilities

#### Missing Salt and Weak Parameters
- **Issue**: Unsalted password hashes and weak bcrypt rounds result in vulnerable hashing.  
  - **Fix**: Add salt to password hashing and enforce a minimum of 12 bcrypt rounds.

#### Argon2 Default or Weak Parameters
- **Issue**: Default or weak Argon2 parameters reduce resistance to brute-force attacks.  
  - **Fix**: Enforce strong parameters for Argon2: `time_cost ≥ 2`, `memory_cost ≥ 65536`, and `parallelism ≥ 2`.

---

### 5. Protocol and Key Management Vulnerabilities

#### Deprecated Protocols
- **Issue**: Older protocols (e.g., SSLv3) are insecure.  
  - **Fix**: Upgrade to modern protocols like TLS 1.3.

#### Hardcoded Keys and Credentials
- **Issue**: Storing keys and credentials in source code exposes them to theft.  
  - **Fix**: Move keys and credentials to environment variables.

#### No Certificate Validation
- **Issue**: SSL/TLS connections without certificate validation are vulnerable to man-in-the-middle attacks.  
  - **Fix**: Enable certificate validation in SSL/TLS connections.

---

### 6. Deprecated Elliptic Curve Cryptography (ECC) Curves

#### ECC with Deprecated Curves
- **Issue**: Weak ECC curves (e.g., SECP112R1) are insecure.  
  - **Fix**: Replace deprecated curves with modern alternatives like SECP256R1 or X25519.

---

### 7. Random Number Generator (RNG) Vulnerabilities

#### Weak PRNGs
- **Issue**: Using insecure random number generators for cryptographic purposes compromises security.  
  - **Fix**: Replace weak PRNGs with secure alternatives like Python's `secrets` module.

#### Weak PRNG for Key Generation
- **Issue**: Weak PRNGs like `random.choices` are unsuitable for generating cryptographic keys.  
  - **Fix**: Replace PRNGs used for key generation with secure alternatives like Python's `secrets.choice`.

---


## Technical Implementation

The simulator builds on the architecture of the cryptographic inventory tool, leveraging modular components for flexibility and maintainability.

### Fix Handling Workflow

1. **AST-Based Fix Generation**
   - AST transformations are used to modify code while preserving functionality. Example:
     ```python
     # Before
     cipher = AES.new(key, AES.MODE_ECB)
     encrypted = cipher.encrypt(data)
     
     # After applying fix
     cipher = AES.new(key, AES.MODE_GCM)
     encrypted, tag = cipher.encrypt_and_digest(data)
     ```
   - Users can preview and apply fixes with confidence in the correctness of the changes.

2. **Database Integration**
   - Fixes and their statuses are tracked in a SQLite database.
   - The database stores:
     - Original code (for reversion).
     - Modified code (post-fix).
     - Fix type and status.

3. **Dynamic Fix Selection**
   - The selection triggers a real-time preview of the changes in the code display.

4. **Reversion Logic**
   - Reversions fetch and restore the original code from the database, ensuring the simulator can undo changes without external dependencies.

### Compliance Monitoring

The simulator evaluates proposed fixes against compliance checklists derived from standards like NIST. Non-compliant fixes are flagged, and alternative options are suggested where available.