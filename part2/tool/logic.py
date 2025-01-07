# logic.py
import sqlite3
import ast
import astor

class CryptoFixer:
    def __init__(self, db_name="crypto_findings.db"):
        self.db_name = db_name

    def fetch_findings(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings")
        rows = cursor.fetchall()
        conn.close()
        return rows

    def apply_fix(self, file_path, changes):
        """Apply AST-based changes to a file."""
        try:
            with open(file_path, 'r') as file:
                tree = ast.parse(file.read(), filename=file_path)

            for change in changes:
                tree = change(tree)  # Apply each change to the AST

            # Write the modified code back to the file
            with open(file_path, 'w') as file:
                file.write(astor.to_source(tree))

            return True
        except Exception as e:
            return f"Failed to apply changes to {file_path}: {e}"

    def is_fixable(self, primitive):
        """Check if the issue is fixable programmatically."""
        fixable_primitives = {"AES", "DES", "3DES", "RSA"}  # Extendable
        return primitive in fixable_primitives

    def get_fix_options(self, primitive):
        """Return a list of fixes for a given primitive."""
        options = {
            # Symmetric Encryption Fixes
            "AES": ["Replace with AES-GCM", "Replace with AES-CCM"],
            "DES": ["Replace with AES-GCM"],
            "3DES": ["Replace with AES-GCM"],
            
            # Asymmetric Encryption Fixes
            "RSA": ["Upgrade to RSA-3072", "Migrate to PQC"],
            "Diffie-Hellman": ["Upgrade to RSA-3072", "Migrate to PQC"],
            
            # Hash Functions Fixes
            "MD5": ["Replace with SHA-256"],
            "SHA1": ["Replace with SHA-256"],
            
            # Weak PRNG Fixes
            "Weak PRNG": ["Replace with secure PRNG (e.g., secrets module)"],
            
            # Password Hashing Fixes
            "PasswordHash_NoSalt": ["Add salt to hashing"],
            "bcrypt_weak_rounds": ["Increase bcrypt rounds to 12 or more"],
            
            # ECC Fixes
            "ECC_DeprecatedCurve": ["Replace with SECP256R1 or X25519"],
            
            # Protocol Fixes
            "NoCertValidation_SSL": ["Enable certificate validation"],
            "NoCertValidation_Requests": ["Enable certificate validation"],
            "NoCertValidation_Urllib": ["Enable certificate validation"],
            
            # Cipher Mode Fixes
            "Static_IV": ["Replace with randomized IV"],
            "ECB_Mode": ["Replace with AES-GCM or AES-CCM"],
            "GCM_NoTagCheck": ["Add GCM tag verification"],
            
            # Hardcoded Key Fixes
            "Hardcoded Key": ["Move to environment variable"],
            "Hardcoded_Credentials": ["Move credentials to environment variables"],
            
            # Deprecated Protocols Fixes
            "Deprecated Protocol": ["Upgrade to modern protocols like TLS 1.3"],
            
            # Miscellaneous
            "Argon2_WeakParams": ["Use stronger parameters: time_cost >= 2, memory_cost >= 65536, parallelism >= 2"]
        }

        return options.get(primitive, ["Manual Fix Required"])

    def generate_ast_changes(self, primitive, fix):
        """Generate AST changes based on the selected fix."""
        changes = []

        # AES: Replace with AES-GCM or AES-CCM
        if primitive == "AES" and fix in ["Replace with AES-GCM", "Replace with AES-CCM"]:
            mode = "GCM" if fix == "Replace with AES-GCM" else "CCM"

            def replace_aes_mode(tree):
                class AESModeTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                            for kw in node.keywords:
                                if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and kw.value.value == "ECB":
                                    kw.value = ast.Constant(value=mode)
                        return node

                return AESModeTransformer().visit(tree)

            changes.append(replace_aes_mode)

        # Diffie-Hellman: Migrate to PQC
        if primitive == "Diffie-Hellman" and fix in ["Upgrade to RSA-3072", "Migrate to PQC"]:
            def upgrade_dh_to_rsa(tree):
                print("Upgrading Diffie-Hellman to RSA")
                class UpgradeDHToRSATransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate_parameters":
                            # Replace Diffie-Hellman parameter generation with RSA private key generation
                            return ast.Call(
                                func=ast.Attribute(value=ast.Name(id="rsa", ctx=ast.Load()), attr="generate_private_key", ctx=ast.Load()),
                                args=[],
                                keywords=[
                                    ast.keyword(arg="public_exponent", value=ast.Constant(value=65537)),
                                    ast.keyword(arg="key_size", value=ast.Constant(value=3072)),
                                ]
                            )
                        return node

                return UpgradeDHToRSATransformer().visit(tree)

            changes.append(upgrade_dh_to_rsa)

        # RSA: Upgrade to RSA-3072 or Migrate to PQC
        if primitive == "RSA" and fix in ["Upgrade to RSA-3072", "Migrate to PQC"]:
            def upgrade_rsa_key(tree):
                class UpgradeRSAKeyTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate":
                            for kw in node.keywords:
                                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                                    kw.value = ast.Constant(value=3072)
                        return node

                return UpgradeRSAKeyTransformer().visit(tree)

            changes.append(upgrade_rsa_key)

        # DES or 3DES: Replace with AES-GCM
        if primitive in ["DES", "3DES"] and fix == "Replace with AES-GCM":
            def replace_des_with_aes(tree):
                class ReplaceDESWithAESGCMTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                            for kw in node.keywords:
                                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                                    kw.value = ast.Constant(value="GCM")
                            node.func.value.id = "AES"  # Replace DES/3DES with AES
                        return node

                return ReplaceDESWithAESGCMTransformer().visit(tree)

            changes.append(replace_des_with_aes)

        # Static IVs: Replace with Randomized IV
        if primitive == "Static_IV" and fix == "Replace with randomized IV":
            def replace_static_iv(tree):
                class ReplaceStaticIVTransformer(ast.NodeTransformer):
                    def visit_Assign(self, node):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id == "iv":
                                node.value = ast.Call(
                                    func=ast.Attribute(value=ast.Name(id="os", ctx=ast.Load()), attr="urandom", ctx=ast.Load()),
                                    args=[ast.Constant(value=16)],  # 16 bytes for a 128-bit IV
                                    keywords=[]
                                )
                        return node

                return ReplaceStaticIVTransformer().visit(tree)

            changes.append(replace_static_iv)

        # GCM Tag Verification: Add Authentication Tag Check
        if primitive == "GCM_NoTagCheck" and fix == "Add GCM tag verification":
            def add_gcm_tag_verification(tree):
                class AddGCMTagVerificationTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "decrypt":
                            # Wrap decrypt call with tag verification logic
                            node = ast.Call(
                                func=ast.Name(id="verify_gcm_tag", ctx=ast.Load()),
                                args=[node],
                                keywords=[]
                            )
                        return node

                return AddGCMTagVerificationTransformer().visit(tree)

            changes.append(add_gcm_tag_verification)

        # Hardcoded Keys: Move to Environment Variables
        if primitive == "Hardcoded Key" and fix == "Move to environment variable":
            def move_key_to_env(tree):
                class MoveKeyToEnvTransformer(ast.NodeTransformer):
                    def visit_Assign(self, node):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id.lower() in ["key", "secret_key"]:
                                node.value = ast.Call(
                                    func=ast.Attribute(value=ast.Name(id="os", ctx=ast.Load()), attr="environ.get", ctx=ast.Load()),
                                    args=[ast.Constant(value=target.id.upper())],
                                    keywords=[]
                                )
                        return node

                return MoveKeyToEnvTransformer().visit(tree)

            changes.append(move_key_to_env)
        
        # bcrypt_weak_rounds: Increase bcrypt rounds to 12 or more
        if primitive == "bcrypt_weak_rounds" and fix == "Increase bcrypt rounds to 12 or more":
            def increase_bcrypt_rounds(tree):
                class IncreaseBcryptRoundsTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "gensalt":
                            for kw in node.keywords:
                                if kw.arg == "rounds" and isinstance(kw.value, ast.Constant) and kw.value.value < 12:
                                    kw.value = ast.Constant(value=12)  # Set rounds to at least 12
                        return node

                return IncreaseBcryptRoundsTransformer().visit(tree)

            changes.append(increase_bcrypt_rounds)

        # Hardcoded_Credentials: Move credentials to environment variables
        if primitive == "Hardcoded_Credentials" and fix == "Move credentials to environment variables":
            def move_credentials_to_env(tree):
                class MoveCredentialsToEnvTransformer(ast.NodeTransformer):
                    def visit_Assign(self, node):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id.upper() in ["USERNAME", "PASSWORD"]:
                                node.value = ast.Call(
                                    func=ast.Attribute(value=ast.Name(id="os", ctx=ast.Load()), attr="environ.get", ctx=ast.Load()),
                                    args=[ast.Constant(value=target.id.upper())],
                                    keywords=[]
                                )
                        return node

                return MoveCredentialsToEnvTransformer().visit(tree)

            changes.append(move_credentials_to_env)

        # Deprecated Protocol: Upgrade to modern protocols like TLS 1.3
        if primitive == "Deprecated Protocol" and fix == "Upgrade to modern protocols like TLS 1.3":
            def upgrade_to_tls13(tree):
                class UpgradeToTLS13Transformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr in ["SSLContext", "create_default_context"]:
                            for kw in node.keywords:
                                if kw.arg == "protocol" and hasattr(kw.value, "attr") and kw.value.attr in ["PROTOCOL_SSLv3", "PROTOCOL_TLSv1"]:
                                    kw.value.attr = "PROTOCOL_TLSv1_3"  # Upgrade to TLS 1.3
                        return node

                return UpgradeToTLS13Transformer().visit(tree)

            changes.append(upgrade_to_tls13)

        # Replace Deprecated Hash Functions
        if primitive in ["MD5", "SHA1"] and fix == "Replace with SHA-256":
            def replace_hash_function(tree):
                class ReplaceHashFunctionTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr in ["md5", "sha1"]:
                            node.func.attr = "sha256"  # Replace with SHA-256
                        return node

                return ReplaceHashFunctionTransformer().visit(tree)

            changes.append(replace_hash_function)

        # Add Salt to Password Hashing
        if primitive == "PasswordHash_NoSalt" and fix == "Add salt to hashing":
            def add_salt_to_hashing(tree):
                class AddSaltToHashingTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr in ["sha256", "sha512"]:
                            salt_node = ast.Call(
                                func=ast.Attribute(value=ast.Name(id="os", ctx=ast.Load()), attr="urandom", ctx=ast.Load()),
                                args=[ast.Constant(value=16)],  # 16 bytes for a 128-bit salt
                                keywords=[]
                            )
                            node.args = [salt_node] + node.args  # Prepend salt to args
                        return node

                return AddSaltToHashingTransformer().visit(tree)

            changes.append(add_salt_to_hashing)

        # Replace Deprecated ECC Curves
        if primitive == "ECC_DeprecatedCurve" and fix == "Replace with SECP256R1":
            def replace_ecc_curve(tree):
                class ReplaceECCCurveTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate_private_key":
                            for kw in node.keywords:
                                if kw.arg == "curve" and hasattr(kw.value, "attr") and "SECP" in kw.value.attr:
                                    kw.value.attr = "SECP256R1"  # Replace with a secure curve
                        return node

                return ReplaceECCCurveTransformer().visit(tree)

            changes.append(replace_ecc_curve)

        # Replace Weak PRNG with Secure PRNG
        if primitive == "Weak PRNG" and fix == "Replace with secure PRNG":
            def replace_prng(tree):
                class ReplacePRNGTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr in ["randint", "random"]:
                            node.func = ast.Attribute(value=ast.Name(id="secrets", ctx=ast.Load()), attr="randbelow", ctx=ast.Load())
                            node.args = [ast.Constant(value=1000000)]  # Example upper limit for randbelow
                        return node

                return ReplacePRNGTransformer().visit(tree)

            changes.append(replace_prng)
        
        # Add Certificate Validation in SSL
        if primitive in ["NoCertValidation_SSL", "NoCertValidation_Requests"] and fix == "Enable certificate validation":
            def enable_cert_validation(tree):
                class EnableCertValidationTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr in ["_create_unverified_context", "requests.get"]:
                            for kw in node.keywords:
                                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                    kw.value.value = True  # Enable certificate validation
                        return node

                return EnableCertValidationTransformer().visit(tree)

            changes.append(enable_cert_validation)

        return changes

