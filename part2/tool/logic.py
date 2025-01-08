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
                source_code = file.read()
                tree = ast.parse(source_code, filename=file_path)

            print("Original Code:")
            print(source_code)

            for change in changes:
                tree = change(tree)  # Apply each change to the AST
                print("After Change:")
                print(astor.to_source(tree))  # Debug transformed AST to source code

            # Fix missing locations in AST
            tree = ast.fix_missing_locations(tree)

            # Write the modified code back to the file
            with open(file_path, 'w') as file:
                modified_code = astor.to_source(tree)
                file.write(modified_code)

            print("Final Transformed Code:")
            print(modified_code)

            return True
        except Exception as e:
            print(f"Error during transformation: {e}")
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
        print(f"Debug: Primitive={primitive}, Fix={fix}") 
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
        if primitive == "Diffie-Hellman" and fix == "Upgrade to RSA-3072":
            def upgrade_dh_to_rsa(tree):
                class UpgradeDHToRSATransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        # Look for calls to dh.generate_parameters
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate_parameters":
                            # Replace with RSA.generate_private_key
                            return ast.Call(
                                func=ast.Attribute(value=ast.Name(id="rsa", ctx=ast.Load()), attr="generate_private_key", ctx=ast.Load()),
                                args=[],
                                keywords=[
                                    ast.keyword(arg="public_exponent", value=ast.Constant(value=65537)),
                                    ast.keyword(arg="key_size", value=ast.Constant(value=3072)),
                                ]
                            )
                        # Replace generate_private_key associated with Diffie-Hellman
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate_private_key":
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

        if primitive == "Diffie-Hellman" and fix == "Migrate to PQC":
            def migrate_to_pqc(tree):
                class MigrateToPQCTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        # Replace calls to dh.generate_parameters with Kyber's generate_keypair
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate_parameters":
                            return ast.Call(
                                func=ast.Attribute(value=ast.Name(id="kyber", ctx=ast.Load()), attr="generate_keypair", ctx=ast.Load()),
                                args=[],
                                keywords=[]
                            )
                        # Replace generate_private_key with the Kyber keypair generation
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate_private_key":
                            return ast.Call(
                                func=ast.Attribute(value=ast.Name(id="kyber", ctx=ast.Load()), attr="generate_keypair", ctx=ast.Load()),
                                args=[],
                                keywords=[]
                            )
                        return node

                return MigrateToPQCTransformer().visit(tree)

            changes.append(migrate_to_pqc)

        # RSA: Upgrade to RSA-3072 or Migrate to PQC
        if primitive == "RSA" and fix in ["Upgrade to RSA-3072", "Migrate to PQC"]:
            def upgrade_rsa_key(tree):
                class UpgradeRSAKeyTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate":
                            # Update the key_size keyword argument to 3072
                            for kw in node.keywords:
                                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                                    kw.value = ast.Constant(value=3072)
                            # If key_size is not explicitly provided, add it
                            if not any(kw.arg == "key_size" for kw in node.keywords):
                                node.keywords.append(
                                    ast.keyword(arg="key_size", value=ast.Constant(value=3072))
                                )
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
                    def __init__(self):
                        self.import_os_added = False

                    def visit_Import(self, node):
                        # Check if `os` is already imported
                        for alias in node.names:
                            if alias.name == "os":
                                self.import_os_added = True
                        return node

                    def visit_Module(self, node):
                        # Add `import os` if it's not already imported
                        self.generic_visit(node)
                        if not self.import_os_added:
                            import_os = ast.Import(names=[ast.alias(name="os", asname=None)])
                            node.body.insert(0, import_os)
                        return node

                    def visit_Assign(self, node):
                        # Detect hardcoded symmetric or RSA keys dynamically
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            # Use the variable name as the environment variable key
                            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                                variable_name = node.targets[0].id.upper()  # Convert variable name to uppercase for ENV key
                                original_value = node.value

                                # Replace with os.environ.get
                                node.value = ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="os", ctx=ast.Load()),
                                        attr="environ.get",
                                        ctx=ast.Load(),
                                    ),
                                    args=[
                                        ast.Constant(value=variable_name),  # Environment variable key
                                        original_value,  # Default value
                                    ],
                                    keywords=[],
                                )
                        return node

                return MoveKeyToEnvTransformer().visit(tree)

            changes.append(move_key_to_env)
        
        # bcrypt_weak_rounds: Increase bcrypt rounds to 12 or more
        if primitive == "bcrypt_weak_rounds" and fix == "Increase bcrypt rounds to 12 or more":
            def increase_bcrypt_rounds(tree):
                class IncreaseBcryptRoundsTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        # Check if the function call is gensalt
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "gensalt":
                            for kw in node.keywords:
                                if kw.arg == "rounds" and isinstance(kw.value, ast.Constant):
                                    # Update rounds to 12 if they are less than 12
                                    if kw.value.value < 12:
                                        kw.value = ast.Constant(value=12)
                        return self.generic_visit(node)  # Continue visiting other nodes

                return IncreaseBcryptRoundsTransformer().visit(tree)


            changes.append(increase_bcrypt_rounds)

        # Hardcoded_Credentials: Move credentials to environment variables
        if primitive == "Hardcoded_Credentials" and fix == "Move credentials to environment variables":
            def move_credentials_to_env(tree):
                class MoveCredentialsToEnvTransformer(ast.NodeTransformer):
                    def __init__(self):
                        self.import_os_added = False

                    def visit_Import(self, node):
                        # Check if `os` is already imported
                        for alias in node.names:
                            if alias.name == "os":
                                self.import_os_added = True
                        return node

                    def visit_Module(self, node):
                        # Add `import os` if it's not already imported
                        self.generic_visit(node)
                        if not self.import_os_added:
                            import_os = ast.Import(names=[ast.alias(name="os", asname=None)])
                            node.body.insert(0, import_os)
                        return node

                    def visit_Assign(self, node):
                        # Detect hardcoded credentials dynamically
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            # Use the variable name as the environment variable key
                            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                                variable_name = node.targets[0].id.upper()  # Convert variable name to uppercase for ENV key
                                original_value = node.value

                                # Replace with os.environ.get
                                node.value = ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="os", ctx=ast.Load()),
                                        attr="environ.get",
                                        ctx=ast.Load(),
                                    ),
                                    args=[
                                        ast.Constant(value=variable_name),  # Environment variable key
                                        original_value,  # Default value
                                    ],
                                    keywords=[],
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
                        # Handle direct `hashlib` calls
                        if (
                            isinstance(node.func, ast.Attribute)
                            and isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "hashlib"
                            and node.func.attr in ["md5", "sha1", "sha224"]  # Extendable
                        ):
                            print(f"Replacing {node.func.attr} with sha256")
                            node.func.attr = "sha256"

                        # Traverse arguments of the function call
                        for i, arg in enumerate(node.args):
                            if (
                                isinstance(arg, ast.Attribute)
                                and isinstance(arg.value, ast.Name)
                                and arg.value.id == "hashlib"
                                and arg.attr in ["md5", "sha1", "sha224"]
                            ):
                                print(f"Replacing nested {arg.attr} with sha256")
                                arg.attr = "sha256"

                        return self.generic_visit(node)

                return ReplaceHashFunctionTransformer().visit(tree)

            changes.append(replace_hash_function)  # Ensure this line matches the block's indentation


        # Add Salt to Password Hashing
        if primitive == "PasswordHash_NoSalt" and fix == "Add salt to hashing":
            def add_salt_to_hashing(tree):
                class AddSaltToHashingTransformer(ast.NodeTransformer):
                    def visit_Module(self, node):
                        import_os = ast.Import(names=[ast.alias(name="os", asname=None)])
                        has_os_import = any(
                            isinstance(stmt, ast.Import) and any(alias.name == "os" for alias in stmt.names)
                            for stmt in node.body
                        )
                        if not has_os_import:
                            node.body.insert(0, import_os)
                        return self.generic_visit(node)

                    def visit_Assign(self, node):
                        # Check if this is a hash function (including chained calls)
                        if (
                            isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Attribute)
                            and isinstance(node.value.func.value, ast.Call)
                            and isinstance(node.value.func.value.func, ast.Attribute)
                            and isinstance(node.value.func.value.func.value, ast.Name)
                            and node.value.func.value.func.value.id == "hashlib"  # Ensure it's a hashlib call
                            and node.value.func.value.func.attr in ["sha256", "sha512"]
                        ):
                            # Generate a random salt
                            salt_assignment = ast.Assign(
                                targets=[ast.Name(id="salt", ctx=ast.Store())],
                                value=ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="os", ctx=ast.Load()),
                                        attr="urandom",
                                        ctx=ast.Load(),
                                    ),
                                    args=[ast.Constant(value=16)],  # 16 bytes for a 128-bit salt
                                    keywords=[],
                                ),
                            )
                            # Combine salt with password before hashing
                            salted_password = ast.BinOp(
                                left=ast.Name(id="salt", ctx=ast.Load()),
                                op=ast.Add(),
                                right=node.value.func.value.args[0],  # Original password
                            )
                            # Update the hash operation to use salted password
                            node.value.func.value.args[0] = salted_password
                            # Insert the salt generation before the current assignment
                            return [salt_assignment, node]

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
        if primitive == "Weak PRNG" and fix == "Replace with secure PRNG (e.g., secrets module)":
            def replace_prng(tree):
                class ReplacePRNGTransformer(ast.NodeTransformer):
                    def __init__(self):
                        self.import_secrets_added = False  # Track if `secrets` import exists

                    def visit_Import(self, node):
                        # Check if `secrets` is already imported
                        for alias in node.names:
                            if alias.name == "secrets":
                                self.import_secrets_added = True
                        return node

                    def visit_ImportFrom(self, node):
                        # Check if `secrets` is already imported with `from` statement
                        if node.module == "secrets":
                            self.import_secrets_added = True
                        return node

                    def visit_Module(self, node):
                        # Add `import secrets` if not already present
                        self.generic_visit(node)
                        if not self.import_secrets_added:
                            import_secrets = ast.Import(names=[ast.alias(name="secrets", asname=None)])
                            node.body.insert(0, import_secrets)
                        return node

                    def visit_Call(self, node):
                        # Replace `random.choice` with `secrets.choice`
                        if (
                            isinstance(node.func, ast.Attribute)
                            and isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "random"
                            and node.func.attr == "choice"
                        ):
                            return ast.Call(
                                func=ast.Attribute(value=ast.Name(id="secrets", ctx=ast.Load()), attr="choice", ctx=ast.Load()),
                                args=node.args,
                                keywords=[],
                            )
                        return self.generic_visit(node)

                return ReplacePRNGTransformer().visit(tree)

            changes.append(replace_prng)

        
        # Add Certificate Validation in SSL
        if primitive == "NoCertValidation_SSL" and fix == "Enable certificate validation":
            def enable_cert_validation(tree):
                class EnableCertValidationTransformer(ast.NodeTransformer):
                    def visit_Call(self, node):
                        if (
                            isinstance(node.func, ast.Attribute)
                            and hasattr(node.func, 'attr')
                            and node.func.attr == "_create_unverified_context"
                        ):
                            print(f"Replacing _create_unverified_context at line {node.lineno}")  # Debug
                            # Update function name to `create_default_context`
                            node.func.attr = "create_default_context"
                        return self.generic_visit(node)

                return EnableCertValidationTransformer().visit(tree)

            changes.append(enable_cert_validation)


        return changes

