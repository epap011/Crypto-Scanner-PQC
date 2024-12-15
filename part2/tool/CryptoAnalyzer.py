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
                                        if key_size < 2048:  # Example for RSA quantum vulnerability
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

                    # Detect hardcoded keys in assignments
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                                if target.id.lower() in ['key', 'secret_key', 'aes_key']:
                                    key_value = node.value.value
                                    if isinstance(key_value, str) and len(key_value) >= 32:  # Assuming long keys
                                        results.append({
                                            'file': file_path,
                                            'primitive': 'Hardcoded Key',
                                            'parameters': f'Key={key_value}',
                                            'issue': 'Hardcoded cryptographic key detected.',
                                            'severity': 'Critical',
                                            'suggestion': 'Avoid embedding keys directly in code.',
                                            'quantum_vulnerable': False
                                        })

                    # Detect concatenated values (e.g., IV or Key)
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

                    # Detect Argon2 weak parameters
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'PasswordHasher':
                            arg_map = {kw.arg: getattr(kw.value, 'value', None) for kw in node.keywords}
                            time_cost = arg_map.get('time_cost', 1)
                            memory_cost = arg_map.get('memory_cost', 1024)
                            parallelism = arg_map.get('parallelism', 1)
                            if time_cost < 2 or memory_cost < 65536 or parallelism < 2:
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

                    # Detect missing GCM tag verification
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'decrypt' and 'MODE_GCM' in ast.dump(node):
                            results.append({
                                'file': file_path,
                                'primitive': 'AES',
                                'parameters': 'MODE_GCM',
                                'issue': 'Missing GCM authentication tag verification.',
                                'severity': 'Critical',
                                'suggestion': 'Ensure authentication tag is verified during decryption.',
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
