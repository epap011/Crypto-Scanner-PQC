#CryptoAnalyzer.py
import os
import re
import ast
import logging

class CryptoAnalyzer:
    def __init__(self, patterns, rules, deprecated_apis, mosca_params):
        self.patterns        = patterns
        self.rules           = rules
        self.deprecated_apis = deprecated_apis
        self.mosca_params    = mosca_params

    def mosca_inequality(self):
        """Evaluate if immediate migration is needed using Mosca's Inequality."""
        X, Y, Z = self.mosca_params
        return (X + Y) >= Z

    def scan_python_ast(self, file_path):
        """Scan a Python file using its AST for specific API calls."""
        results = []
        try:
            with open(file_path, 'r') as file:
                tree = ast.parse(file.read(), filename=file_path)
                for node in ast.walk(tree):
                    # Check for deprecated APIs in function/method calls
                    if isinstance(node, ast.Attribute):
                        full_attr = f"{getattr(node.value, 'id', '')}.{node.attr}"  # Build full attribute name
                        if full_attr in self.deprecated_apis:
                            severity, issue, suggestion = self.deprecated_apis[full_attr]
                            results.append({
                                'file': file_path,
                                'primitive': full_attr,
                                'parameters': None,
                                'issue': issue,
                                'severity': severity,
                                'suggestion': suggestion,
                                'quantum_vulnerable': False
                            })
                    # Detect weak PRNG usage
                    if isinstance(node, ast.Name) and node.id == 'random':
                        results.append({
                            'file': file_path,
                            'primitive': 'Weak PRNG',
                            'parameters': None,
                            'issue': 'Weak PRNG detected.',
                            'severity': 'High',
                            'suggestion': 'Replace with `secrets` module.',
                            'quantum_vulnerable': False
                        })
        except Exception as e:
            logging.error(f"Error parsing AST for file {file_path}: {e}")
        return results

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