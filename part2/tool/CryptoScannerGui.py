#CryptoScannerGui.py
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

        findings = self.analyzer.scan_directory(directory)
        prioritized_findings = self.analyzer.prioritize_findings(findings)
        self.db_manager.save_findings(prioritized_findings)

        messagebox.showinfo("Scan Complete", "Scan completed. Findings saved to the database.")

    def export_to_csv(self):
        self.db_manager.export_findings_to_csv()
    
    def view_results(self):
        rows = self.db_manager.fetch_all_findings()

        if not rows:
            messagebox.showinfo("No Results", "No findings to display.")
            return

        result_window = tk.Toplevel(self.root)
        result_window.title("Scan Results")

        # Create Treeview widget
        tree = ttk.Treeview(
            result_window, 
            columns=("File", "Primitive", "Severity", "Issue"), 
            show='headings'
        )
        tree.heading("File", text="File")
        tree.heading("Primitive", text="Primitive")
        tree.heading("Severity", text="Severity")
        tree.heading("Issue", text="Issue")
        tree.pack(fill=tk.BOTH, expand=True)

        # Define severity-based row styles
        tree.tag_configure('Critical', background='#FFCCCC')  # Light red for Critical
        tree.tag_configure('High', background='#FFD580')      # Light orange for High
        tree.tag_configure('Medium', background='#FFFFCC')    # Light yellow for Medium
        tree.tag_configure('Low', background='#CCFFCC')       # Light green for Low

        # Populate Treeview with findings
        for row in rows:
            severity = row[5]  # Assuming 'severity' is at index 5 in the database row
            tag = severity  # Use severity as tag name
            tree.insert("", tk.END, values=(row[1], row[2], row[5], row[4]), tags=(tag,))


