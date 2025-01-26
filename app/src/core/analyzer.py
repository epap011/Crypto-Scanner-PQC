# CryptoAnalyzer.py
import os
import re
import ast
import logging

class CryptoAnalyzer:
    def __init__(self, patterns, rules, deprecated_apis, mosca_params):
        self.patterns = patterns
        self.rules = rules
        self.deprecated_apis = deprecated_apis
        self.mosca_params = mosca_params

    def mosca_inequality(self):
        """Evaluate if immediate migration is needed using Mosca's Inequality."""
        X, Y, Z = self.mosca_params
        return (X + Y) >= Z

    def scan_python_ast(self, file_path):
        """Scan a Python file using its AST for specific vulnerabilities."""
        results = []
        try:
            with open(file_path, 'r') as file:
                tree = ast.parse(file.read(), filename=file_path)
                for node in ast.walk(tree):
                    # Detect key size assignments
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                                if target.id.lower() in ['key_size', 'rsa_key_size', 'ecc_key_size']:
                                    key_size = node.value.value
                                    if isinstance(key_size, int):
                                        if key_size < 2048:
                                            results.append({
                                                'file': file_path,
                                                'primitive': 'RSA',
                                                'parameters': f'key_size={key_size}',
                                                'issue': 'RSA key size is quantum-vulnerable.',
                                                'severity': 'Critical' if key_size < 2048 else 'High',
                                                'suggestion': 'Use RSA key size >= 3072 or PQC alternatives.',
                                                'quantum_vulnerable': True
                                            })

                    # Detect key size passed as arguments in function calls
                    if isinstance(node, ast.Call):
                        for keyword in node.keywords:
                            if keyword.arg in ['key_size', 'modulus_size']:
                                key_size = getattr(keyword.value, 'value', None)
                                if isinstance(key_size, int) and key_size < 2048:
                                    results.append({
                                        'file': file_path,
                                        'primitive': 'RSA',
                                        'parameters': f'key_size={key_size}',
                                        'issue': 'RSA key size is quantum-vulnerable.',
                                        'severity': 'Critical' if key_size < 2048 else 'High',
                                        'suggestion': 'Use RSA key size >= 3072 or PQC alternatives.',
                                        'quantum_vulnerable': True
                                    })

                    # Detect static IVs in assignments
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                                if target.id.lower() in ['iv', 'initialization_vector']:
                                    iv_value = node.value.value
                                    if isinstance(iv_value, str) and iv_value.startswith("0x"):
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'Static_IV',
                                            'parameters': f'IV={iv_value}',
                                            'issue': 'Static IV detected; this is insecure.',
                                            'severity': 'Critical',
                                            'suggestion': 'Use a randomized IV for each encryption operation.',
                                            'quantum_vulnerable': False
                                        })

                    # Detect hardcoded keys in assignments (both symmetric and asymmetric)
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                                # Check for keys, including symmetric and asymmetric types
                                if target.id.lower() in ['key', 'secret_key', 'aes_key', 'private_key']:
                                    key_value = node.value.value
                                    # Detect long symmetric keys (>= 32 bytes)
                                    if isinstance(key_value, str) and len(key_value) >= 32:
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'Hardcoded Key',
                                            'parameters': f'Key={key_value}',
                                            'issue': 'Hardcoded symmetric cryptographic key detected.',
                                            'severity': 'Critical',
                                            'suggestion': 'Avoid embedding keys directly in code. Use environment variables or secure storage.',
                                            'quantum_vulnerable': False
                                        })
                                    # Detect PEM-encoded RSA private keys
                                    if isinstance(key_value, str) and "BEGIN RSA PRIVATE KEY" in key_value:
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'Hardcoded Key',
                                            'parameters': f'Key={key_value}',
                                            'issue': 'Hardcoded RSA private key detected.',
                                            'severity': 'Critical',
                                            'suggestion': 'Avoid embedding private keys directly in code. Use secure key management solutions.',
                                            'quantum_vulnerable': False
                                        })


                    # Detect concatenated values
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and isinstance(node.value, ast.BinOp):
                                if target.id.lower() in ['iv', 'key']:
                                    concat_value = self._resolve_concat(node.value)
                                    if target.id.lower() == 'iv' and concat_value.startswith("0x"):
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'Static_IV',
                                            'parameters': f'IV={concat_value}',
                                            'issue': 'Static IV detected in concatenation; this is insecure.',
                                            'severity': 'Critical',
                                            'suggestion': 'Use a randomized IV for each encryption operation.',
                                            'quantum_vulnerable': False
                                        })

                    # Detect Argon2 weak parameters or default parameter usage
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'PasswordHasher':
                            # Map all arguments passed to PasswordHasher()
                            arg_map = {kw.arg: getattr(kw.value, 'value', None) for kw in node.keywords}
                            time_cost = arg_map.get('time_cost', 1)  # Default time_cost
                            memory_cost = arg_map.get('memory_cost', 1024)  # Default memory_cost
                            parallelism = arg_map.get('parallelism', 1)  # Default parallelism

                            # Check for default parameters (no arguments provided)
                            if not arg_map:  # Defaults used
                                results.append({
                                    'file': file_path,
                                    'primitive': 'Argon2',
                                    'parameters': 'Default Parameters',
                                    'issue': 'Argon2 used with default parameters, which may be weak.',
                                    'severity': 'Medium',
                                    'suggestion': 'Specify secure parameters: time_cost >= 2, memory_cost >= 65536, parallelism >= 2.',
                                    'quantum_vulnerable': False
                                })

                            # Check for explicitly weak parameters
                            elif time_cost < 2 or memory_cost < 65536 or parallelism < 2:
                                results.append({
                                    'file': file_path,
                                    'primitive': 'Argon2',
                                    'parameters': f'time_cost={time_cost}, memory_cost={memory_cost}, parallelism={parallelism}',
                                    'issue': 'Weak Argon2 parameters.',
                                    'severity': 'Critical',
                                    'suggestion': 'Use time_cost >= 2, memory_cost >= 65536, parallelism >= 2.',
                                    'quantum_vulnerable': False
                                })


                    # Detect bcrypt weak rounds
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'gensalt':
                            for keyword in node.keywords:
                                if keyword.arg == 'rounds':
                                    rounds = getattr(keyword.value, 'value', None)
                                    if rounds and rounds < 12:
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'bcrypt',
                                            'parameters': f'rounds={rounds}',
                                            'issue': 'Weak bcrypt rounds.',
                                            'severity': 'Critical',
                                            'suggestion': 'Use bcrypt.gensalt(rounds=12) or higher.',
                                            'quantum_vulnerable': False
                                        })

                    # Detect AES GCM mode decryption without authentication tag verification
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        # Check if AES.new is called with MODE_GCM
                        if node.func.attr == 'new' and any(arg for arg in node.args if hasattr(arg, 'id') and arg.id == 'MODE_GCM'):
                            # Walk through the AST to check for decrypt calls on the same cipher object
                            decrypt_call = any(
                                isinstance(child, ast.Call) and child.func.attr == 'decrypt' for child in ast.walk(node)
                            )
                            if decrypt_call:
                                results.append({
                                    'file': file_path,
                                    'primitive': 'AES',
                                    'parameters': 'MODE_GCM',
                                    'issue': 'Missing GCM tag verification during decryption.',
                                    'severity': 'Critical',
                                    'suggestion': 'Verify the authentication tag during decryption.',
                                    'quantum_vulnerable': False
                                })

                    # Detect usage of deprecated SSL/TLS protocols
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['SSLContext', 'create_default_context']:
                            for keyword in node.keywords:
                                if keyword.arg == 'protocol' and hasattr(keyword.value, 'attr'):
                                    if keyword.value.attr in ['PROTOCOL_SSLv3', 'PROTOCOL_TLSv1']:
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'TLS',
                                            'parameters': f'Protocol={keyword.value.attr}',
                                            'issue': 'Deprecated SSL/TLS protocol detected.',
                                            'severity': 'Critical',
                                            'suggestion': 'Update to TLS 1.2 or 1.3 with secure ciphers.',
                                            'quantum_vulnerable': False
                                        })

                    # Detect usage of weak PRNGs for key generation
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['randint', 'choice', 'shuffle', 'random']:
                            results.append({
                                'file': file_path,
                                'primitive': 'Weak PRNG',
                                'parameters': f'Method={node.func.attr}',
                                'issue': 'Using a weak PRNG for cryptographic purposes.',
                                'severity': 'Critical',
                                'suggestion': 'Use a cryptographically secure PRNG like `secrets` or `os.urandom`.',
                                'quantum_vulnerable': False
                            })

                    # Detect AES usage with insecure ECB mode
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'new' and 'AES.MODE_ECB' in ast.dump(node):
                            results.append({
                                'file': file_path,
                                'primitive': 'AES',
                                'parameters': 'MODE_ECB',
                                'issue': 'AES in ECB mode is insecure.',
                                'severity': 'Critical',
                                'suggestion': 'Switch to a secure mode like GCM or CCM.',
                                'quantum_vulnerable': False
                            })

                    # Detect Key Material Reuse in HKDF
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        if node.func.id == 'HKDF':
                            # Track the reuse of key material in the same file
                            key_materials = []
                            for arg in node.args:
                                if isinstance(arg, ast.Constant):
                                    key_materials.append(arg.value)
                            if len(set(key_materials)) < len(key_materials):
                                results.append({
                                    'file': file_path,
                                    'primitive': 'KeyReuse_KDF',
                                    'parameters': 'Reused Key Material',
                                    'issue': 'Reused key material in HKDF derivation.',
                                    'severity': 'Critical',
                                    'suggestion': 'Use unique salts and diversify derivation inputs.',
                                    'quantum_vulnerable': False
                                })

                    # Detect Deprecated Protocol References in Strings
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Str):
                        if any(proto in node.value.s for proto in ['TLSv1.0', 'SSLv3', 'IKEv1']):
                            results.append({
                                'file': file_path,
                                'primitive': 'Deprecated Protocol',
                                'parameters': node.value.s,
                                'issue': 'Deprecated protocol detected in a string reference.',
                                'severity': 'Critical',
                                'suggestion': 'Update to modern protocols like TLS 1.3.',
                                'quantum_vulnerable': False
                            })


        except Exception as e:
            logging.error(f"Error parsing AST for file {file_path}: {e}")
        return results

    def _resolve_concat(self, bin_op_node):
        """Resolve concatenated string values in AST BinOp nodes."""
        if isinstance(bin_op_node.left, ast.Constant) and isinstance(bin_op_node.right, ast.Constant):
            return f"{bin_op_node.left.value}{bin_op_node.right.value}"
        return "Unknown"

    def scan_file(self, file_path):
        """Scan a single file for cryptographic issues."""
        results = []
        # Use regex-based scanning
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                for key, pattern in self.patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = ', '.join(match)
                        if callable(self.rules[key]):  # For rules that depend on parameters
                            severity, issue, suggestion = self.rules[key](match)
                        else:
                            severity, issue, suggestion = self.rules[key]
                        quantum_vulnerable = key in ['RSA', 'ECC', 'ECDH', 'ECDSA', 'Diffie-Hellman']
                        results.append({
                            'file': file_path,
                            'primitive': key,
                            'parameters': match if match else None,
                            'issue': issue,
                            'severity': severity,
                            'suggestion': suggestion,
                            'quantum_vulnerable': quantum_vulnerable
                        })
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")

        # Use AST-based scanning
        results.extend(self.scan_python_ast(file_path))
        return results

    def scan_directory(self, directory):
        """Recursively scan a directory for cryptographic issues."""
        findings = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    results = self.scan_file(file_path)
                    findings.extend(results)
        return findings

    def prioritize_findings(self, findings):
        for finding in findings:
            finding['mosca_urgent'] = self.mosca_inequality() and finding.get('quantum_vulnerable', False)
        findings.sort(key=lambda x: ('Critical', 'High', 'Medium', 'Low').index(x['severity']))
        return findings
