import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from logic import CryptoFixer

import ast
import astor

class CryptoScannerGUI:
    def __init__(self, root, analyzer, db_manager):
        self.root = root
        self.analyzer = analyzer
        self.db_manager = db_manager
        self.fixer = CryptoFixer()

        self.setup_ui()

    def setup_ui(self):
        self.root.title("Cryptographic Scanner")
        self.root.config(bg="#2E2E2E")
        self.root.geometry("900x600")

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
        messagebox.showinfo("Scan Complete", f"Scan completed for directory: {directory}")

    def export_to_csv(self):
        self.db_manager.export_findings_to_csv()

    def view_results(self):
        rows = self.db_manager.fetch_all_findings()
        if not rows:
            messagebox.showinfo("No Results", "No findings to display.")
            return

        def search_results(event=None):
            search_term = search_entry.get().lower()
            filtered_rows = [row for row in rows if search_term in str(row[1]).lower()]
            self.populate_tree(tree, filtered_rows)
            update_statistics(filtered_rows)

        def sort_treeview(tree, col, reverse):
            # Retrieve data from the Treeview
            data = [(tree.set(child, col), child) for child in tree.get_children("")]
            # Sort data based on the column
            data.sort(key=lambda t: t[0], reverse=reverse)
            # Rearrange items in sorted order
            for index, (val, child) in enumerate(data):
                tree.move(child, '', index)
            # Reverse the sorting for the next click
            tree.heading(col, command=lambda: sort_treeview(tree, col, not reverse))


        def update_statistics(filtered_rows):
            critical_count = sum(1 for row in filtered_rows if row[5] == 'Critical')
            high_count     = sum(1 for row in filtered_rows if row[5] == 'High')
            medium_count   = sum(1 for row in filtered_rows if row[5] == 'Medium')
            low_count      = sum(1 for row in filtered_rows if row[5] == 'Low')

            auto_fix_count = sum(1 for row in filtered_rows if self.fixer.get_fix_options(row[2]) != ["Manual Fix Required"])
            manual_fix_count = sum(1 for row in filtered_rows if self.fixer.get_fix_options(row[2]) == ["Manual Fix Required"])

            critical_label.config(text=f"Critical: {critical_count}")
            high_label.config(text=f"High: {high_count}")
            medium_label.config(text=f"Medium: {medium_count}")
            low_label.config(text=f"Low: {low_count}")

            auto_fix_label.config(text=f"Automatic Fix Exists: {auto_fix_count}")
            manual_fix_label.config(text=f"Manual Intervention Required: {manual_fix_count}")

        result_window = tk.Toplevel(self.root)
        result_window.title("Scan Results")
        result_window.geometry("1000x600")

        search_frame = tk.Frame(result_window)
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        search_label = tk.Label(search_frame, text="Search:", font=("Courier", 12))
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        search_entry = tk.Entry(search_frame, font=("Courier", 12))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        search_entry.bind("<KeyRelease>", search_results)

        stats_frame = tk.Frame(result_window)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)

        critical_label = tk.Label(stats_frame, text="Critical: 0", font=("Courier", 12), fg="#FF0000")
        critical_label.pack(side=tk.LEFT, padx=(0, 15))

        high_label = tk.Label(stats_frame, text="High: 0", font=("Courier", 12), fg="#FFA500")
        high_label.pack(side=tk.LEFT, padx=(0, 15))

        medium_label = tk.Label(stats_frame, text="Medium: 0", font=("Courier", 12), fg="#42b357")
        medium_label.pack(side=tk.LEFT, padx=(0, 15))

        low_label = tk.Label(stats_frame, text="Low: 0", font=("Courier", 12), fg="#407fc2")
        low_label.pack(side=tk.LEFT, padx=(0, 15))

        auto_fix_label = tk.Label(stats_frame, text="Automatic Fix Exists: 0", font=("Courier", 12), fg="#008000")
        auto_fix_label.pack(side=tk.RIGHT, padx=(15, 0))

        manual_fix_label = tk.Label(stats_frame, text="Manual Intervention Required: 0", font=("Courier", 12), fg="#FF4500")
        manual_fix_label.pack(side=tk.RIGHT, padx=(15, 0))

        tree = ttk.Treeview(
            result_window,
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

        self.populate_tree(tree, rows)
        update_statistics(rows)

        def on_double_click(event):
            selected_item = tree.selection()
            if not selected_item:
                return
            selected_item = selected_item[0]
            fix_type = tree.item(selected_item, 'values')[-1]
            if fix_type == "Manual Intervention Required":
                return
            self.fix_selected_file(tree)

        tree.bind("<Double-1>", on_double_click)

    def populate_tree(self, treeview, data):
        for item in treeview.get_children():
            treeview.delete(item)
        for row in data:
            # Dynamically determine the fix type
            primitive = row[2]
            fix_options = self.fixer.get_fix_options(primitive)
            if fix_options and fix_options != ["Manual Fix Required"]:
                fix_type = "Automatic fix exists"
            else:
                fix_type = "Manual Intervention Required"
            severity = row[5]
            tag = severity
            treeview.insert("", tk.END, values=(row[1], row[2], row[4], row[5], row[6], fix_type), tags=(tag,))

    def fix_selected_file(self, tree):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a file to fix.")
            return
        
        selected_item = selected_item[0]
        # Unpack including the new "Fix Type" column
        file, primitive, issue, severity, solution, fix_type = tree.item(selected_item, 'values')

        if solution == "Manual Intervention Required":
            messagebox.showwarning(
                "Manual Intervention Required",
                f"The issue in {file} with {primitive} requires manual intervention."
            )
            return

        self.show_fix_modal(file, primitive, issue)


    def show_fix_modal(self, file, primitive, issue):
        modal = tk.Toplevel(self.root)
        modal.title("Fix Cryptographic Issue")
        modal.geometry("800x600")

        # Layout for original and updated code side-by-side
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

        # Enable scrolling for the code views
        scrollbar = tk.Scrollbar(code_frame, orient=tk.VERTICAL, command=original_code.yview)
        scrollbar.grid(row=1, column=2, sticky="ns")
        original_code.config(yscrollcommand=scrollbar.set)

        scrollbar2 = tk.Scrollbar(code_frame, orient=tk.VERTICAL, command=updated_code.yview)
        scrollbar2.grid(row=1, column=3, sticky="ns")
        updated_code.config(yscrollcommand=scrollbar2.set)

        code_frame.grid_columnconfigure(0, weight=1)
        code_frame.grid_columnconfigure(1, weight=1)
        code_frame.grid_rowconfigure(1, weight=1)

        # Load and display the original code
        with open(file, 'r') as f:
            source_code = f.read()
            original_code.insert(tk.END, source_code)
            original_code.config(state=tk.DISABLED)

        # Dropdown for selecting fixes
        tk.Label(modal, text="Select Fix:", font=("Courier", 12)).pack(pady=10)
        fixes = self.fixer.get_fix_options(primitive)

        selected_fix = tk.StringVar()
        dropdown = ttk.Combobox(modal, values=fixes, textvariable=selected_fix)
        dropdown.pack(pady=10)

        def preview_fix(*args):
            fix = selected_fix.get()
            if not fix:
                return

            # Generate changes and apply them to the original code
            changes = self.fixer.generate_ast_changes(primitive, fix)
            if changes:
                try:
                    tree = ast.parse(source_code, filename=file)
                    for change in changes:
                        tree = change(tree)  # Apply each change
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

        # Save changes button
        def save_changes():
            fix = selected_fix.get()
            if not fix:
                messagebox.showerror("Error", "Please select a fix.")
                return

            changes = self.fixer.generate_ast_changes(primitive, fix)
            if changes:
                try:
                    tree = ast.parse(source_code, filename=file)
                    for change in changes:
                        tree = change(tree)  # Apply each change
                    modified_code = astor.to_source(tree)

                    with open(file, 'w') as f:
                        f.write(modified_code)
                    messagebox.showinfo("Success", f"Changes saved to {file}.")
                    modal.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save changes: {e}")

        save_button = tk.Button(modal, text="Save Changes", command=save_changes, font=("Courier", 12))
        save_button.pack(pady=20)
