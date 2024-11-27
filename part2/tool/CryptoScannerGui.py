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

        tk.Label(self.root, text="Directory to Scan:").grid(row=0, column=0, padx=10, pady=10)
        self.directory_entry = tk.Entry(self.root, width=50)
        self.directory_entry.grid(row=0, column=1, padx=10, pady=10)

        browse_button = tk.Button(self.root, text="Browse", command=self.browse_directory)
        browse_button.grid(row=0, column=2, padx=10, pady=10)

        scan_button = tk.Button(self.root, text="Run Scan", command=self.run_scan)
        scan_button.grid(row=1, column=0, columnspan=3, pady=10)

        view_button = tk.Button(self.root, text="View Results", command=self.view_results)
        view_button.grid(row=2, column=0, columnspan=3, pady=10)

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

        findings = self.analyzer.scan_directory(directory)
        prioritized_findings = self.analyzer.prioritize_findings(findings)
        self.db_manager.save_findings(prioritized_findings)

        messagebox.showinfo("Scan Complete", "Scan completed. Findings saved to the database.")

    def view_results(self):
        rows = self.db_manager.fetch_all_findings()

        result_window = tk.Toplevel(self.root)
        result_window.title("Scan Results")
        tree = ttk.Treeview(result_window, columns=("File", "Primitive", "Severity", "Issue"), show='headings')
        tree.heading("File", text="File")
        tree.heading("Primitive", text="Primitive")
        tree.heading("Severity", text="Severity")
        tree.heading("Issue", text="Issue")
        tree.pack(fill=tk.BOTH, expand=True)
        for row in rows:
            tree.insert("", tk.END, values=(row[1], row[2], row[5], row[4]))
