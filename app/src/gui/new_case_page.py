import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from tkinter.simpledialog import askstring
from core.analyzer import CryptoAnalyzer
from core.database_manager import DatabaseManager
from core.logic import CryptoFixer
from matplotlib.figure import Figure 
from matplotlib.backends.backend_tkagg import (FigureCanvasTkAgg, NavigationToolbar2Tk)
import matplotlib.pyplot as plt 
import ast
import astor

class NewCasePage:
    def __init__(self, parent_panel):
        self.parent_panel = parent_panel

        self.define_patterns()
        self.define_rules()
        self.define_deprecated_apis()

        self.analyzer   = CryptoAnalyzer(self.patterns, self.rules, self.deprecated_apis, mosca_params=(10, 5, 15))
        self.db_manager = DatabaseManager()
        self.fixer      = CryptoFixer()

        self.prioritized_findings = []
        self.auto_fix_count = 0
        self.manual_fix_count = 0

    def show(self):
        self.actions_panel = tk.Frame(self.parent_panel, bg="#2E2E2E", height=150, highlightthickness=2, highlightbackground="green", highlightcolor="green")
        self.actions_panel.pack(side=tk.TOP, fill=tk.X)

        self.statistics_panel = tk.Frame(self.parent_panel, bg="#3D3D3D", height=150)
        self.statistics_panel.pack(side=tk.BOTTOM, fill=tk.X)

        self.main_content = tk.Frame(self.parent_panel, bg="#3D3D3D")
        self.main_content.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        self.init_actions_panel()

    def init_actions_panel(self):
        self.directory_entry = tk.Entry(
            self.actions_panel,
            width=30,
            font=("Courier", 10),
            fg="black",
            bg="#C0C0C0",
            bd=0,
            relief="flat"
        )
        self.directory_entry.grid(row=1, column=1, padx=10, pady=10, ipadx=5, ipady=5)
        self.directory_entry.insert(0, "Select a directory to scan...")

        browse_button = tk.Button(
            self.actions_panel,
            text="Browse",
            font=("Courier", 10, "bold"),
            height=1,
            fg="white",
            bg="#00B140",
            activebackground="#4CAF50",
            activeforeground="white",
            bd=0,
            relief="flat",
            command=self.browse_directory
        )
        browse_button.grid(row=1, column=2, padx=10, pady=10, ipadx=5, ipady=5)

        scan_button = tk.Button(
            self.actions_panel,
            text="Run Scan",
            font=("Courier", 10, "bold"),
            fg="white",
            bg="#FF5722",
            activebackground="#FF7043",
            activeforeground="white",
            bd=0,
            relief="flat",
            command=self.run_scan_and_view_results
        )
        scan_button.grid(row=1, column=3, padx=10, pady=10, ipadx=5, ipady=5)

        save_button = tk.Button(
            self.actions_panel,
            text="Save Case",
            font=("Courier", 10, "bold"),
            fg="white",
            bg="#2758ed",
            activebackground="#5b7de3",
            activeforeground="white",
            bd=0,
            relief="flat",
            command=self.save_case
        )
        save_button.grid(row=1, column=4, padx=10, pady=10, ipadx=5, ipady=5)

    def browse_directory(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, folder_selected)

    def run_scan_and_view_results(self):
        self.prioritized_findings = []
        for widget in self.main_content.winfo_children():
            widget.destroy()
        for widget in self.statistics_panel.winfo_children():
            widget.destroy()

        self.directory = self.directory_entry.get()
        if self.directory == "Select a directory to scan...":
            messagebox.showerror("Error", "Please select a directory to scan.")
            return
        
        self.run_scan()
        self.view_scan_results()

    def run_scan(self):
        self.directory = self.directory_entry.get()
        if self.directory == "Select a directory to scan...":
            return

        findings = self.analyzer.scan_directory(self.directory)
        self.prioritized_findings = self.analyzer.prioritize_findings(findings)

    def view_scan_results(self):
        def search_results(event=None):
            search_term = search_entry.get().lower()
            filtered_rows = [
                row for row in rows 
                if search_term in row['file'].lower() or search_term in row['primitive'].lower()
            ]
            self.populate_tree(tree, filtered_rows)
            update_statistics(filtered_rows)

        def sort_treeview(tree, col, reverse):
            # Retrieve data from the Treeview
            data = [(tree.set(child, col), child) for child in tree.get_children("")]
            # Sort data based on the column
            data.sort(key=lambda t: t[0].lower() if isinstance(t[0], str) else t[0], reverse=reverse)
            # Rearrange items in sorted order
            for index, (val, child) in enumerate(data):
                tree.move(child, '', index)
            # Reverse the sorting for the next click
            tree.heading(col, command=lambda: sort_treeview(tree, col, not reverse))

        def update_statistics(filtered_rows):
            self.critical_count = sum(1 for row in filtered_rows if row['severity'] == 'Critical')
            self.high_count     = sum(1 for row in filtered_rows if row['severity'] == 'High')
            self.medium_count   = sum(1 for row in filtered_rows if row['severity'] == 'Medium')
            self.low_count      = sum(1 for row in filtered_rows if row['severity'] == 'Low')

            self.rsa_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'RSA')
            self.ecc_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'ECC')
            self.aes_related_count = sum(1 for row in filtered_rows if row['primitive'].startswith('AES'))
            self.des_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'DES')
            self.md5_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'MD5')
            self.sha1_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'SHA-1')
            self.sha256_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'SHA-256')
            self.tls_related_count = sum(1 for row in filtered_rows if row['primitive'] == 'TLS')

        def populate_tree(tree, rows):
            tree.delete(*tree.get_children())
            for row in rows:
                fix_options = self.fixer.get_fix_options(row['primitive'])
                if fix_options and fix_options != ["Manual Fix Required"]:
                    fix_type = "Automatic fix exists"
                    self.auto_fix_count += 1
                else:
                    fix_type = "Manual Intervention Required"
                    self.manual_fix_count += 1

                severity = row['severity']
                tree.insert(
                    "",
                    "end",
                    values=(
                        row['file'],
                        row['primitive'],
                        row['issue'],
                        row['severity'],
                        row['suggestion'],
                        fix_type
                    ),
                    tags=(severity,)
                )

        rows = self.prioritized_findings

        search_frame = tk.Frame(self.main_content, bg="#3D3D3D")
        search_frame.pack(fill=tk.X, padx=250, pady=5)

        search_label = tk.Label(search_frame, text="Search:", font=("Courier", 12), fg="white", bg="#2E2E2E")
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        search_entry = tk.Entry(search_frame, font=("Courier", 12))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        search_entry.bind("<KeyRelease>", search_results)

        tree = ttk.Treeview(
            self.main_content,
            columns=("File", "Primitive", "Issue", "Severity", "Solution", "Fix"),
            show='headings'
        )
        
        for col in ("File", "Primitive", "Issue", "Severity", "Solution", "Fix"):
            tree.heading(col, text=col, command=lambda _col=col: sort_treeview(tree, _col, False))
        tree.pack(fill=tk.BOTH, expand=True)

        tree.tag_configure('Critical', background='#FFCCCC')
        tree.tag_configure('High'    , background='#FFD580')
        tree.tag_configure('Medium'  , background='#FFFFCC')
        tree.tag_configure('Low'     , background='#CCFFCC')

        populate_tree(tree, rows)
        update_statistics(rows)
        self.show_statistic_pies()

        def on_double_click(event):
            selected_item = tree.selection()
            if not selected_item:
                return
            selected_item = selected_item[0]
            fix_type = tree.item(selected_item, 'values')[-1]
            if fix_type == "Manual Intervention Required":
                messagebox.showwarning(
                    "Manual Intervention Required",
                    f"This issue requires manual intervention."
                )
                return
            self.fix_selected_file(tree)

        tree.bind("<Double-1>", on_double_click)

    def show_statistic_pies(self):
        stats_frame = tk.Frame(self.statistics_panel, bg="#3D3D3D")
        stats_frame.pack(fill=tk.X, padx=0, pady=5)

        critical_label = tk.Label(stats_frame, text="Critical: 0", font=("Courier", 12), fg="#FF0000", bg="#3D3D3D")
        critical_label.pack(side=tk.LEFT, padx=(0, 15))

        high_label = tk.Label(stats_frame, text="High: 0", font=("Courier", 12), fg="#FFA500", bg="#3D3D3D")
        high_label.pack(side=tk.LEFT, padx=(0, 15))

        medium_label = tk.Label(stats_frame, text="Medium: 0", font=("Courier", 12), fg="#42b357", bg="#3D3D3D")
        medium_label.pack(side=tk.LEFT, padx=(0, 15))

        low_label = tk.Label(stats_frame, text="Low: 0", font=("Courier", 12), fg="#407fc2", bg="#3D3D3D")
        low_label.pack(side=tk.LEFT, padx=(0, 15))

        auto_fix_label = tk.Label(stats_frame, text="Automatic Fix Exists: 0", font=("Courier", 12), fg="#008000", bg="#3D3D3D")
        auto_fix_label.pack(side=tk.RIGHT, padx=(15, 0))

        manual_fix_label = tk.Label(stats_frame, text="Manual Intervention Required: 0", font=("Courier", 12), fg="#FF4500", bg="#3D3D3D")
        manual_fix_label.pack(side=tk.RIGHT, padx=(15, 0))

        critical_label.config(text=f"Critical: {self.critical_count}")
        high_label.config(text=f"High: {self.high_count}")
        medium_label.config(text=f"Medium: {self.medium_count}")
        low_label.config(text=f"Low: {self.low_count}")

        auto_fix_label.config(text=f"Automatic Fix Exists: {self.auto_fix_count}")
        manual_fix_label.config(text=f"Manual Intervention Required: {self.manual_fix_count}")
        
        categories = [
            "RSA", "ECC", "AES", "DES", "MD5",
            "SHA-1", "SHA-256", "TLS"
        ]
        counts = [
            self.rsa_related_count,
            self.ecc_related_count,
            self.aes_related_count,
            self.des_related_count,
            self.md5_related_count,
            self.sha1_related_count,
            self.sha256_related_count,
            self.tls_related_count
        ]

        params = {"ytick.color" : "w",
          "xtick.color" : "w",
          "axes.labelcolor" : "w",
          "axes.edgecolor" : "w"}
        plt.rcParams.update(params)

        # Create the Matplotlib figure for the bar chart
        fig = Figure(figsize=(4, 2), dpi=100, facecolor="#3D3D3D")  # Smaller figure size
        ax = fig.add_subplot(111)

        # Plotting the bar chart with custom colors
        ax.bar(categories, counts, color="green", width=0.6)
        ax.set_xlabel("Algorithms", fontsize=8)
        ax.set_ylabel("Count", fontsize=8)
        ax.tick_params(axis='x', labelsize=8, rotation=45)
        ax.tick_params(axis='y', labelsize=8)
        ax.set_facecolor('#3D3D3D')

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.statistics_panel)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.BOTTOM)

    def populate_tree(self, treeview, data):
        for item in treeview.get_children():
            treeview.delete(item)
        for row in data:
            # Include `finding_id` (row[0]) as part of the TreeView values
            finding_id = row[0]
            primitive = row[2]
            fix_options = self.fixer.get_fix_options(primitive)
            if fix_options and fix_options != ["Manual Fix Required"]:
                fix_type = "Automatic fix exists"
            else:
                fix_type = "Manual Intervention Required"
            severity = row[5]
            status = row[9]
            tag = severity
            treeview.insert("", tk.END, values=(finding_id, row[1], row[2], row[4], row[5], row[6], fix_type, status),tags=(tag,) )
        #treeview.tag_configure('Critical', background='#FFCCCC')

    def define_patterns(self):
        self.patterns = {
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

    def define_rules(self):
        self.rules = {
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

    def define_deprecated_apis(self):
        self.deprecated_apis = {
            'ssl.PROTOCOL_TLSv1': ('Critical', 'Deprecated SSL/TLS protocol detected.', 'Update to TLS 1.2 or 1.3.'),
            'paramiko.DSSKey': ('Critical', 'Deprecated SSH key type detected.', 'Use Ed25519 or RSA with >=2048 bits.')
        }
    
    def fix_selected_file(self, tree):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a file to fix.")
            return

        selected_item = selected_item[0]
        # Assuming `finding_id` is the first column in the TreeView data``
        finding_id = -1
        file, primitive, issue, severity, solution, fix_type = tree.item(selected_item, 'values')
        
        if solution == "Manual Intervention Required":
            messagebox.showwarning(
                "Manual Intervention Required",
                f"The issue in {file} with {primitive} requires manual intervention."
            )
            return

        # Pass all required arguments, including finding_id
        self.show_fix_modal(finding_id, file, primitive, issue)

    def show_fix_modal(self, finding_id, file, primitive, issue):
        modal = tk.Toplevel(self.parent_panel)
        modal.title("Fix Cryptographic Issue")
        modal.geometry("800x900")

        tk.Label(modal, text=f"File: {file}", font=("Courier", 12)).pack(pady=5)
        tk.Label(modal, text=f"Primitive: {primitive}", font=("Courier", 12)).pack(pady=5)
        tk.Label(modal, text=f"Issue: {issue}", font=("Courier", 12)).pack(pady=5)

        code_frame = tk.Frame(modal)
        code_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        original_label = tk.Label(code_frame, text="Original Code", font=("Courier", 12))
        original_label.grid(row=0, column=0, padx=5, pady=5)

        updated_label = tk.Label(code_frame, text="Updated Code", font=("Courier", 12))
        updated_label.grid(row=0, column=1, padx=5, pady=5)

        original_code = tk.Text(code_frame, wrap=tk.NONE, font=("Courier", 10), bg="#F0F0F0", height=25)
        original_code.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        updated_code = tk.Text(code_frame, wrap=tk.NONE, font=("Courier", 10), bg="#F0F0F0", height=25)
        updated_code.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        scrollbar = tk.Scrollbar(code_frame, orient=tk.VERTICAL, command=original_code.yview)
        scrollbar.grid(row=1, column=2, sticky="ns")
        original_code.config(yscrollcommand=scrollbar.set)

        scrollbar2 = tk.Scrollbar(code_frame, orient=tk.VERTICAL, command=updated_code.yview)
        scrollbar2.grid(row=1, column=3, sticky="ns")
        updated_code.config(yscrollcommand=scrollbar2.set)

        code_frame.grid_columnconfigure(0, weight=1)
        code_frame.grid_columnconfigure(1, weight=1)
        code_frame.grid_rowconfigure(1, weight=1)

        with open(file, 'r') as f:
            source_code = f.read()
            original_code.insert(tk.END, source_code)
            original_code.config(state=tk.DISABLED)

        tk.Label(modal, text="Select Fix:", font=("Courier", 12)).pack(pady=10)
        fixes = self.fixer.get_fix_options(primitive)

        selected_fix = tk.StringVar()
        dropdown = ttk.Combobox(modal, values=fixes, textvariable=selected_fix)
        dropdown.pack(pady=10)

        def preview_fix(*args):
            fix = selected_fix.get()
            if not fix:
                return
            changes = self.fixer.generate_ast_changes(primitive, fix)
            if changes:
                try:
                    tree = ast.parse(source_code, filename=file)
                    for change in changes:
                        tree = change(tree)
                    modified_code = astor.to_source(tree)

                    updated_code.config(state=tk.NORMAL)
                    updated_code.delete(1.0, tk.END)
                    updated_code.insert(tk.END, modified_code)
                    updated_code.config(state=tk.DISABLED)
                except Exception as e:
                    updated_code.config(state=tk.NORMAL)
                    updated_code.delete(1.0, tk.END)
                    updated_code.insert(tk.END, f"Error applying fix: {e}")
                    updated_code.config(state=tk.DISABLED)

        dropdown.bind("<<ComboboxSelected>>", preview_fix)

        def save_changes():
            print("Saving changes...")
            fix = selected_fix.get()
            if not fix:
                messagebox.showerror("Error", "Please select a fix.")
                return

            changes = self.fixer.generate_ast_changes(primitive, fix)
            if changes:
                try:
                    tree = ast.parse(source_code, filename=file)
                    for change in changes:
                        tree = change(tree)
                    modified_code = astor.to_source(tree)

                    # Save the modified code back to the file
                    with open(file, 'w') as f:
                        f.write(modified_code)

                    # Update the status using the DatabaseManager
                    # self.db_manager.update_finding_status(finding_id, 'fixed')

                    # Notify the user and close the modal
                    messagebox.showinfo("Success", f"Changes saved to {file} and status updated to 'fixed'.")
                    modal.destroy()

                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save changes: {e}")

        save_button = tk.Button(modal, text="Save Changes", command=save_changes, font=("Courier", 12))
        save_button.pack(pady=20)

        def revert_changes():
            original_code_content = self.db_manager.fetch_original_code(finding_id)
            if original_code_content:
                with open(file, 'w') as f:
                    f.write(original_code_content)
                
                self.db_manager.update_finding_status(finding_id, 'not_fixed')
                messagebox.showinfo("Reverted", f"Changes reverted to original code for {file}.")
                modal.destroy()
            else:
                messagebox.showerror("Error", "Original code not found in the database.")

        revert_button = tk.Button(modal, text="Revert Changes", command=revert_changes, font=("Courier", 12), bg="#FF0000", fg="white")
        revert_button.pack(pady=10)

    def save_case(self):
        case_name = askstring("Case Name", "Enter the name of the case:")
        if not case_name:
            return

        self.db_manager.store_case(folder_path=self.directory, findings=self.prioritized_findings, case_name=case_name)
