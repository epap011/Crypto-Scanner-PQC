# CryptoScannerGui.py
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


class CryptoScannerGUI:
    def __init__(self, root, analyzer, db_manager):
        self.root       = root
        self.analyzer   = analyzer
        self.db_manager = db_manager

        self.setup_ui()

    def setup_ui(self):
        self.root.title("Cryptographic Scanner")
        self.root.config(bg="#2E2E2E")
        self.root.geometry("600x300")
        self.root.minsize(900, 400)

        title_label = tk.Label(
            self.root, 
            text="Cryptographic Scanner", 
            font=("Courier", 20, "bold"), 
            fg="white", 
            bg="#2E2E2E"
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=20)

        dir_label = tk.Label(
            self.root, 
            text="Directory to Scan:", 
            font=("Courier", 12), 
            fg="white", 
            bg="#2E2E2E"
        )
        dir_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")

        self.directory_entry = tk.Entry(
            self.root, 
            width=50, 
            font=("Courier", 12), 
            fg="black", 
            bg="#C0C0C0", 
            bd=0, 
            relief="flat"
        )
        self.directory_entry.grid(row=1, column=1, padx=10, pady=10, ipadx=5, ipady=5)

        browse_button = tk.Button(
            self.root, 
            text="Browse", 
            font=("Courier", 12), 
            fg="white", 
            bg="#00B140", 
            activebackground="#4CAF50", 
            activeforeground="white", 
            bd=0, 
            relief="flat", 
            command=self.browse_directory
        )
        browse_button.grid(row=1, column=2, padx=10, pady=10, ipadx=5, ipady=5)

        # Align buttons on the same row (row=2)
        scan_button = tk.Button(
            self.root, 
            text="Run Scan", 
            font=("Courier", 12, "bold"), 
            fg="white", 
            bg="#FF5722", 
            activebackground="#FF7043", 
            activeforeground="white", 
            bd=0, 
            relief="flat", 
            command=self.run_scan
        )
        scan_button.grid(row=2, column=0, padx=20, pady=20, ipadx=20, ipady=10)

        view_button = tk.Button(
            self.root, 
            text="View Results", 
            font=("Courier", 12), 
            fg="white", 
            bg="#3F51B5", 
            activebackground="#5C6BC0", 
            activeforeground="white", 
            bd=0, 
            relief="flat", 
            command=self.view_results
        )
        view_button.grid(row=2, column=1, padx=20, pady=20, ipadx=20, ipady=10)

        export_button = tk.Button(
            self.root, 
            text="Export to CSV", 
            font=("Courier", 12), 
            fg="white", 
            bg="#FF9800", 
            activebackground="#FFC107", 
            activeforeground="white", 
            bd=0, 
            relief="flat", 
            command=self.export_to_csv
        )
        export_button.grid(row=2, column=2, padx=20, pady=20, ipadx=20, ipady=10)

        self.status_label = tk.Label(
            self.root, 
            text="Status: Ready", 
            font=("Courier", 10), 
            fg="white", 
            bg="#2E2E2E"
        )
        self.status_label.grid(row=3, column=0, columnspan=3, pady=10)

        for row in range(4):
            self.root.grid_rowconfigure(row, weight=1, minsize=50)

        for col in range(3):
            self.root.grid_columnconfigure(col, weight=1, minsize=150)

    def browse_directory(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, folder_selected)

    def run_scan(self):
        directory = self.directory_entry.get()
        if not directory:
            messagebox.showerror("Error", "Please select a directory to scan.")
            return
        # Run the scan
        findings = self.analyzer.scan_directory(directory)
        prioritized_findings = self.analyzer.prioritize_findings(findings)
        self.db_manager.save_findings(prioritized_findings)
        # Gather scan statistics
        file_counts = {"python": 0, "java": 0, "other": 0}
        vulnerable_counts = {"python": 0, "java": 0, "other": 0}
        scanned_files = [finding['file'] for finding in findings]
        vulnerable_files = {file: [] for file in scanned_files}

        for file in scanned_files:
            if file.endswith('.py'):
                file_counts["python"] += 1
            elif file.endswith('.java'):
                file_counts["java"] += 1
            else:
                file_counts["other"] += 1

        for finding in findings:
            file = finding['file']
            if file not in vulnerable_files:
                vulnerable_files[file] = []
            vulnerable_files[file].append(finding)
            if file.endswith('.py'):
                vulnerable_counts["python"] += 1
            elif file.endswith('.java'):
                vulnerable_counts["java"] += 1
            else:
                vulnerable_counts["other"] += 1

        # Prepare statistics message
        stats_message = (
            f"Scan Complete!\n\n"
            f"Number of files scanned:\n"
            f" - Python: {file_counts['python']}\n"
            f"Number of vulnerable files discovered:\n"
            f" - Python: {vulnerable_counts['python']}\n"
        )
        messagebox.showinfo("Scan Statistics", stats_message)

    def export_to_csv(self):
        self.db_manager.export_findings_to_csv()
    
    def view_results(self):
        rows = self.db_manager.fetch_all_findings()
        if not rows:
            messagebox.showinfo("No Results", "No findings to display.")
            return

        result_window = tk.Toplevel(self.root)
        result_window.title("Scan Results")
        tree = ttk.Treeview(
            result_window, 
            columns=("File", "Primitive", "Severity", "Issue"), 
            show='headings'
        )
        tree.heading("File", text="File", command=lambda: self.sort_tree(tree, rows, column=1))
        tree.heading("Primitive", text="Primitive", command=lambda: self.sort_tree(tree, rows, column=2))
        tree.heading("Severity", text="Severity", command=lambda: self.sort_tree(tree, rows, column=5, sort_key=self.severity_sort_key))
        tree.heading("Issue", text="Issue", command=lambda: self.sort_tree(tree, rows, column=4))
        tree.pack(fill=tk.BOTH, expand=True)

        tree.tag_configure('Critical', background='#FFCCCC')
        tree.tag_configure('High', background='#FFD580')
        tree.tag_configure('Medium', background='#FFFFCC')
        tree.tag_configure('Low', background='#CCFFCC')
        self.populate_tree(tree, rows)

    def populate_tree(self, treeview, data):
        """Clear and repopulate the tree with sorted data."""
        for item in treeview.get_children():
            treeview.delete(item)
        for row in data:
            severity = row[5]
            tag = severity
            treeview.insert("", tk.END, values=(row[1], row[2], row[5], row[4]), tags=(tag,))

    def sort_tree(self, treeview, data, column, sort_key=None):
        """Sort the tree data by the given column."""
        sort_key = sort_key or (lambda x: x[column])
        ascending = getattr(treeview, "sort_ascending", True)
        data.sort(key=lambda x: sort_key(x[column]), reverse=not ascending)
        setattr(treeview, "sort_ascending", not ascending)
        self.populate_tree(treeview, data)

    def severity_sort_key(self, severity):
        """Map severity levels to numeric values for sorting."""
        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        return order.get(severity, 0)

