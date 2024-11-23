import os
import ast
import re
import csv
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import datetime
import logging


# Define cryptographic patterns
patterns = {
    'DES': r'\bDES\b',
    '3DES': r'\b3DES\b',
    'MD5': r'\bMD5\b',
    'SHA1': r'\bSHA-1\b',
    'SHA2_224': r'\bSHA-224\b',
    'RSA': r'\bRSA\b.*?\((.*?)\)',
    'DSA': r'\bDSA\b',
    'ECC': r'\bEllipticCurve\b|\bECC\b',
    'ECDH': r'\bECDH\b',
    'ECDSA': r'\bECDSA\b',
    'AES': r'\bAES\b.*?mode=([A-Z]+)',
    'bcrypt': r'\bbcrypt\b',
    'argon2': r'\bargon2\b',
    'Diffie-Hellman': r'\bDH\b|\bDiffieHellman\b',
    'TLS': r'\bTLSv1\.\d\b|\bSSLv3\b',
    'SSH': r'\bssh-rsa\b|\bssh-dss\b',
    'IPsec': r'\bIKEv1\b',
    'Hardcoded Key': r'([a-fA-F0-9]{32,})|(["\']{5,})',  # Detect long hex or string constants maybe it could be done better
    'Weak PRNG': r'\brandom\.(random|randint|choice|shuffle|uniform)\b',
    'Cryptography Library': r'\bfrom\s+cryptography|import\s+cryptography\b',
    'PyCrypto': r'\bfrom\s+Crypto|import\s+Crypto\b',
    'pycryptodome': r'\bfrom\s+Cryptodome|import\s+Cryptodome\b',
    'Django Cryptography': r'\bdjango\.db\.models\.BinaryField\b',
    'Flask-Security': r'\bflask_security\.utils\b',
    'FastAPI Cryptography': r'\bfastapi_security\b', 
}

deprecated_apis = {
    'ssl.PROTOCOL_TLSv1': ('Critical', 'Deprecated SSL/TLS protocol detected.', 'Update to TLS 1.2 or 1.3.'),
    'paramiko.DSSKey': ('Critical', 'Deprecated SSH key type detected.', 'Use Ed25519 or RSA with >=2048 bits.')
}

# Define risk assessment rules and suggestions
rules = {
    'DES': ('Critical', 'DES is insecure; avoid using.', 'Replace with AES-GCM or AES-CCM'),
    '3DES': ('Critical', '3DES is insecure; avoid using.', 'Replace with AES-GCM or AES-CCM'),
    'MD5': ('Critical', 'MD5 is outdated; replace with SHA-256 or better.', 'Replace with SHA-256 or SHA-3'),
    'SHA1': ('Critical', 'SHA-1 is outdated; replace with SHA-256 or better.', 'Replace with SHA-256 or SHA-3'),
    'SHA2_224': ('Medium', 'SHA-224 is deprecated; prefer SHA-256 or better.', 'Replace with SHA-256 or SHA-3'),
    'RSA': lambda key_size: (
        ('Critical', "Invalid or missing RSA key size; verify manually.", 'Replace with Kyber (PQC)') 
        if not key_size.isdigit() else 
        ('High' if int(key_size) >= 2048 else 'Critical', f"RSA key size {key_size} is quantum-vulnerable; must migrate to PQC.", 'Use Kyber or hybrid schemes.')
    ),
    'ECC': ('High', 'ECC is quantum-vulnerable; transition to PQC.', 'Replace with NTRU or hybrid schemes.'),
    'ECDH': ('High', 'ECDH is quantum-vulnerable; transition to PQC.', 'Use hybrid Diffie-Hellman or Kyber.'),
    'ECDSA': ('High', 'ECDSA is quantum-vulnerable; transition to PQC.', 'Replace with Dilithium (PQC).'),
    'AES': lambda mode: (
        ('Medium' if mode in ['ECB', 'CBC'] else 'Low', f"AES mode {mode} is less secure; prefer GCM or CCM.", 'Switch to GCM or CCM.')
    ),
    'bcrypt': ('Low', 'bcrypt is secure but computationally expensive.', 'Consider Argon2 for new systems.'),
    'argon2': ('Low', 'argon2 is currently secure and recommended.', 'No action needed.'),
    'Diffie-Hellman': ('High', 'Weak DH parameters are quantum-vulnerable; ensure strong group sizes.', 'Use hybrid Diffie-Hellman or Kyber.'),
    'TLS': ('Critical', 'Deprecated TLS version detected.', 'Upgrade to TLS 1.3 with PQC support.'),
    'SSH': ('Critical', 'Weak SSH algorithm detected.', 'Use Ed25519 or PQC alternatives.'),
    'IPsec': ('Critical', 'Deprecated IPsec version detected.', 'Use IKEv2 with PQC support.'),
    'Hardcoded Key': ('Critical', 'Hardcoded cryptographic key detected.', 'Avoid embedding keys directly in code.'),
    'Weak PRNG': ('High', 'Weak PRNG detected; use `secrets` module instead.', 'Replace with `secrets` module.'),
    'Cryptography Library': ('Medium', 'Usage of cryptography library detected. Review its usage for secure practices.', 'Ensure correct key management and secure algorithm selection.'),
    'PyCrypto': ('Critical', 'PyCrypto is outdated and insecure.', 'Replace with `pycryptodome` or other secure libraries.'),
    'pycryptodome': ('Medium', 'pycryptodome detected. Ensure secure practices.', 'Verify secure configurations and key management.'),
    'Django Cryptography': ('Medium', 'Django BinaryField might store sensitive data.', 'Use encrypted fields or dedicated cryptographic tools.'),
    'Flask-Security': ('Medium', 'Flask-Security cryptographic utility detected.', 'Review for weak cryptographic implementations or configurations.'),
    'FastAPI Cryptography': ('Medium', 'FastAPI cryptographic utility detected.', 'Ensure secure configurations and parameter usage.')
}



# Mosca's Inequality Parameters
X = 10  # Data must remain secure for 10 years
Y = 5   # Time to migrate is 5 years
Z = 15  # Estimated time until quantum threat is practical

def mosca_inequality():
    """Evaluate if immediate migration is needed using Mosca's Inequality."""
    return (X + Y) >= Z


def initialize_database(db_name="crypto_findings.db"):
    """Initialize SQLite database and create tables with unique constraints."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT,
            primitive TEXT,
            parameters TEXT,
            issue TEXT,
            severity TEXT,
            suggestion TEXT,
            quantum_vulnerable BOOLEAN,
            mosca_urgent BOOLEAN,
            UNIQUE(file, primitive, parameters)  -- Prevent duplicate entries
        )
    """)
    conn.commit()
    conn.close()


def save_findings_to_db(findings, db_name="crypto_findings.db"):
    """Save findings to the database."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    for finding in findings:
        cursor.execute("""
            INSERT OR IGNORE INTO findings 
            (file, primitive, parameters, issue, severity, suggestion, quantum_vulnerable, mosca_urgent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding['file'], finding['primitive'], finding['parameters'],
            finding['issue'], finding['severity'], finding['suggestion'],
            finding['quantum_vulnerable'], finding['mosca_urgent']
        ))
    conn.commit()
    conn.close()


def export_to_csv():
    """Export findings to a CSV file."""
    conn = sqlite3.connect("crypto_findings.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        messagebox.showinfo("No Data", "No findings to export.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save Findings as CSV"
    )
    if file_path:
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow([
                "ID", "File", "Primitive", "Parameters",
                "Issue", "Severity", "Suggestion", "Quantum Vulnerable", "Mosca Urgent"
            ])
            writer.writerows(rows)
        messagebox.showinfo("Export Complete", f"Findings exported to {file_path}.")


def scan_python_ast(file_path):
    """Scan a Python file using its AST for specific API calls."""
    results = []
    try:
        with open(file_path, 'r') as file:
            tree = ast.parse(file.read(), filename=file_path)
            for node in ast.walk(tree):
                # Check for deprecated APIs in function/method calls
                if isinstance(node, ast.Attribute):
                    full_attr = f"{getattr(node.value, 'id', '')}.{node.attr}"  # Build full attribute name
                    if full_attr in deprecated_apis:
                        severity, issue, suggestion = deprecated_apis[full_attr]
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


def scan_file(file_path):
    """Scan a single file for cryptographic issues."""
    results = []
    # Use regex-based scanning
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            for key, pattern in patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = ', '.join(match)
                    if callable(rules[key]):  # For rules that depend on parameters
                        severity, issue, suggestion = rules[key](match)
                    else:
                        severity, issue, suggestion = rules[key]
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
    results.extend(scan_python_ast(file_path))
    return results


def scan_directory(directory):
    """Recursively scan a directory for cryptographic issues."""
    findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                results = scan_file(file_path)
                findings.extend(results)
    return findings


def prioritize_findings(findings):
    """Prioritize findings based on severity and quantum vulnerability."""
    prioritized = []
    for finding in findings:
        finding['mosca_urgent'] = mosca_inequality() and finding.get('quantum_vulnerable', False)
        prioritized.append(finding)

    # Sort by severity (Critical > High > Medium > Low)
    prioritized.sort(key=lambda x: ('Critical', 'High', 'Medium', 'Low').index(x['severity']))
    return prioritized


# Tkinter GUI
def browse_directory():
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        directory_entry.delete(0, tk.END)
        directory_entry.insert(0, folder_selected)


def run_scan():
    directory = directory_entry.get()
    if not directory:
        messagebox.showerror("Error", "Please select a directory to scan.")
        return

    findings = scan_directory(directory)
    prioritized_findings = prioritize_findings(findings)
    save_findings_to_db(prioritized_findings)

    messagebox.showinfo("Scan Complete", "Scan completed. Findings saved to the database.")


def view_results():
    conn = sqlite3.connect("crypto_findings.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings")
    rows = cursor.fetchall()
    conn.close()

    result_window = tk.Toplevel(root)
    result_window.title("Scan Results")
    tree = ttk.Treeview(result_window, columns=("File", "Primitive", "Severity", "Issue"), show='headings')
    tree.heading("File", text="File")
    tree.heading("Primitive", text="Primitive")
    tree.heading("Severity", text="Severity")
    tree.heading("Issue", text="Issue")
    tree.pack(fill=tk.BOTH, expand=True)
    for row in rows:
        tree.insert("", tk.END, values=(row[1], row[2], row[5], row[4]))


# Main Program
initialize_database()
logging.basicConfig(filename='crypto_scan.log', level=logging.ERROR)

root = tk.Tk()
root.title("Cryptographic Scanner")

tk.Label(root, text="Directory to Scan:").grid(row=0, column=0, padx=10, pady=10)
directory_entry = tk.Entry(root, width=50)
directory_entry.grid(row=0, column=1, padx=10, pady=10)

browse_button = tk.Button(root, text="Browse", command=browse_directory)
browse_button.grid(row=0, column=2, padx=10, pady=10)

scan_button = tk.Button(root, text="Run Scan", command=run_scan)
scan_button.grid(row=1, column=0, columnspan=3, pady=10)

view_button = tk.Button(root, text="View Results", command=view_results)
view_button.grid(row=2, column=0, columnspan=3, pady=10)

export_button = tk.Button(root, text="Export to CSV", command=export_to_csv)
export_button.grid(row=3, column=0, columnspan=3, pady=10)


root.mainloop()