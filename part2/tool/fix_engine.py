# fix_engine.py
import re
import ast
import astor
from typing import List, Dict

# Define algorithm alternatives
algorithm_alternatives = {
    "MD5": "SHA-256",
    "SHA-1": "SHA-256",
    "bcrypt.gensalt(rounds=4)": "bcrypt.gensalt(rounds=12)",
    "AES.MODE_ECB": "AES.MODE_GCM",
    "SSLv3": "TLSv1.3",
    "TLSv1.0": "TLSv1.3",
    "RSA 1024": "RSA 3072",
    # Add more as needed
}

class FixEngine:
    def __init__(self):
        self.alternatives = {
            "hashlib.md5": "hashlib.sha256",
            "hashlib.sha1": "hashlib.sha256",
        }

    def detect_issues(self, file_content: str) -> List[Dict]:
        """
        Detect issues in the given file content.
        Returns a list of issues found, each represented as a dictionary.
        """
        issues = []
        for primitive, alternative in self.alternatives.items():
            if primitive in file_content:
                issues.append({
                    "primitive": primitive,
                    "alternative": alternative,
                    "description": f"Found usage of insecure '{primitive}', suggest replacing with '{alternative}'."
                })
        return issues

    def apply_fix(self, file_content: str) -> str:
        """
        Apply fixes to the given file content.
        Returns the modified content.
        """
        # Use an AST-based approach to properly update HMAC calls
        class HMACFixer(ast.NodeTransformer):
            def visit_Call(self, node):
                # Check if the call is to hmac.new
                if isinstance(node.func, ast.Attribute) or isinstance(node.func, ast.Name):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                        if isinstance(node.args[2], ast.Attribute) and node.args[2].value.id == "hashlib":
                            # Replace MD5 or SHA-1 with SHA-256
                            if node.args[2].attr in ["md5", "sha1"]:
                                node.args[2].attr = "sha256"
                return self.generic_visit(node)

        # Parse the file content into an AST
        tree = ast.parse(file_content)

        # Apply the HMAC fixer
        fixer = HMACFixer()
        fixed_tree = fixer.visit(tree)

        # Generate the modified code
        return astor.to_source(fixed_tree)

    def validate_fix(self, original: str, modified: str) -> bool:
        """
        Validate the fixed content to ensure it meets expectations.
        For now, checks that all insecure primitives are replaced.
        """
        for primitive in self.alternatives.keys():
            if primitive in modified:
                return False
        return True





# Utility Functions
def analyze_and_fix(file_path: str):
    """
    Analyze a file, detect issues, and apply fixes.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        original_content = file.read()

    engine = FixEngine()
    issues = engine.detect_issues(original_content)
    if not issues:
        print(f"No issues found in {file_path}.")
        return original_content, None

    print(f"Issues detected in {file_path}:")
    for issue in issues:
        print(f" - {issue['description']}")

    # Apply fixes
    modified_content = engine.apply_fix(original_content)

    # Validate the fixes
    if engine.validate_fix(original_content, modified_content):
        print(f"Fixes successfully applied to {file_path}.")
    else:
        print(f"Fixes might not be complete for {file_path}, manual review suggested.")

    return original_content, modified_content
