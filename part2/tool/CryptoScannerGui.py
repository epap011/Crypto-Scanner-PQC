# CryptoScannerGui.py
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from logic import CryptoFixer
from PIL import Image, ImageTk

import ast
import astor

class CryptoScannerGUI:
    def __init__(self, root, analyzer, db_manager):
        self.root = root
        self.analyzer = analyzer
        self.db_manager = db_manager
        self.fixer = CryptoFixer()

        self.active_button = None

        self.setup_ui()

    def setup_ui(self):
        self.root.title("Cryptographic Scanner")
        self.root.config(bg="#2E2E2E")
        self.root.geometry("1280x700")

        # Navigation Panel
        self.navigation_panel = tk.Frame(self.root, bg="#1F1F1F", width=300)
        self.navigation_panel.pack(side=tk.LEFT, fill=tk.Y)

        # Actions Panel
        self.actions_panel = tk.Frame(self.root, bg="#3D3D3D", height=80)
        self.actions_panel.pack(side=tk.TOP, fill=tk.X)

        title_label = tk.Label(
            self.navigation_panel,
            text="Crypto Scanner",
            font=("Courier", 20, "bold"),
            fg="white",
            bg="#1F1F1F"
        )
        title_label.pack(pady=20, padx=10)

        # Navigation Panel Buttons
        self.add_navigation_button("Home"         , self.show_home_page)
        self.add_navigation_button("Scan File(s)" , self.show_scan_page)

        # Main Content Panel
        self.main_content = tk.Frame(self.root, bg="#141410")
        self.main_content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        #configure home button to purple
        self.active_button = self.navigation_panel.winfo_children()[1]
        self.handle_nav_button(self.active_button, self.show_home_page)
    
    def add_navigation_button(self, text, command):
        button = tk.Button(
            self.navigation_panel,
            text=text,
            font=("Courier", 12, "bold"),
            fg="white",
            bg="#00B140",
            activebackground="#BF80FF",
            activeforeground="white",
            bd=0,
            relief="flat",
            command=lambda: self.handle_nav_button(button, command)
        )
        button.pack(fill=tk.X, pady=5, padx=10, ipady=10)

    def handle_nav_button(self, button, command):
        if self.active_button:
            self.active_button.configure(bg="#00B140")

        button.configure(bg="#9900E6")
        self.active_button = button

        command()

    def clear_main_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()
        
        for widget in self.actions_panel.winfo_children():
            widget.destroy()

    def show_home_page(self):
        self.clear_main_content()

        tk.Label(
            self.main_content,
            text="Welcome to Crypto Scanner",
            font=("Courier", 16),
            fg="white",
            bg="#2E2E2E"
        ).pack(pady=20)

        tk.Label(
            self.main_content,
            text="This tool helps you identify and fix cryptographic issues in your Python code.",
            font=("Courier", 12),
            fg="white",
            bg="#2E2E2E"
        ).pack(pady=10)

        tk.Label(
            self.main_content,
            text="Use the navigation panel on the left to get started.",
            font=("Courier", 12),
            fg="white",
            bg="#2E2E2E"
        ).pack(pady=10)
        
        self.main_content.update_idletasks()
        frame_width = self.main_content.winfo_width()
        frame_height = self.main_content.winfo_height()

        try:
            image = Image.open("hand.jpg")
            if frame_width > 0 and frame_height > 0:
                image = image.resize((min(image.width, frame_width), min(image.height, frame_height)))
            self.photo = ImageTk.PhotoImage(image)
            image_label = tk.Label(self.main_content, image=self.photo)
            image_label.pack(pady=10)
        except Exception as e:
            tk.Label(
                self.main_content,
                text=f"Error loading image: {e}",
                font=("Courier", 12),
                fg="red",
                bg="#F5F5F5"
            ).pack(pady=10)

    def show_scan_page(self):
        self.clear_main_content()

        dir_label = tk.Label(
            self.actions_panel,
            text="Directory to Scan:",
            font=("Courier", 12),
            fg="white",
            bg="#3D3D3D"
        )
        dir_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")

        self.directory_entry = tk.Entry(
            self.actions_panel,
            width=50,
            font=("Courier", 12),
            fg="black",
            bg="#C0C0C0",
            bd=0,
            relief="flat"
        )
        self.directory_entry.grid(row=0, column=1, padx=10, pady=10, ipadx=5, ipady=5)

        browse_button = tk.Button(
            self.actions_panel,
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
        browse_button.grid(row=0, column=2, padx=10, pady=10, ipadx=5, ipady=5)

        scan_button = tk.Button(
            self.actions_panel,
            text="Run Scan",
            font=("Courier", 12, "bold"),
            fg="white",
            bg="#FF5722",
            activebackground="#FF7043",
            activeforeground="white",
            bd=0,
            relief="flat",
            command=self.run_scan_and_view_results
        )
        scan_button.grid(row=0, column=3, padx=10, pady=10, ipadx=5, ipady=5)

    def show_database_page(self):
        self.clear_main_content()

        tk.Label(
            self.main_content,
            text="Database Management",
            font=("Courier", 16),
            bg="#F5F5F5"
        ).pack(pady=20)

        import_button = tk.Button(
            self.main_content,
            text="Import Database",
            font=("Courier", 12),
            command=self.import_database
        )
        import_button.pack(pady=10)

        export_button = tk.Button(
            self.main_content,
            text="Export Database",
            font=("Courier", 12),
            command=self.export_database
        )
        export_button.pack(pady=10)

        clear_button = tk.Button(
            self.main_content,
            text="Clear Database",
            font=("Courier", 12),
            command=self.clear_database
        )
        clear_button.pack(pady=10)

    def browse_directory(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, folder_selected)

    def run_scan_and_view_results(self):
        self.run_scan()
        self.view_results()

    def run_scan(self):
        directory = self.directory_entry.get()
        if not directory:
            messagebox.showerror("Error", "Please select a directory to scan.")
            return

        findings = self.analyzer.scan_directory(directory)
        prioritized_findings = self.analyzer.prioritize_findings(findings)
        self.db_manager.save_findings(prioritized_findings)

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

            auto_fix_count   = sum(1 for row in filtered_rows if self.fixer.get_fix_options(row[2]) != ["Manual Fix Required"])
            manual_fix_count = sum(1 for row in filtered_rows if self.fixer.get_fix_options(row[2]) == ["Manual Fix Required"])

            critical_label.config(text=f"Critical: {critical_count}")
            high_label.config(text=f"High: {high_count}")
            medium_label.config(text=f"Medium: {medium_count}")
            low_label.config(text=f"Low: {low_count}")

            auto_fix_label.config(text=f"Automatic Fix Exists: {auto_fix_count}")
            manual_fix_label.config(text=f"Manual Intervention Required: {manual_fix_count}")

        search_frame = tk.Frame(self.main_content, bg="#3D3D3D")
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        search_label = tk.Label(search_frame, text="Search:", font=("Courier", 12))
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        search_entry = tk.Entry(search_frame, font=("Courier", 12))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        search_entry.bind("<KeyRelease>", search_results)

        stats_frame = tk.Frame(self.main_content, bg="#3D3D3D")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)

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

        tree = ttk.Treeview(
            self.main_content,
            columns=("ID", "File", "Primitive", "Issue", "Severity", "Solution", "Fix", "Status"),
            show='headings'
        )
        tree.column("ID", width=3, anchor=tk.W)
        tree.pack(fill=tk.BOTH, expand=True)
        
        for col in ("File", "Primitive", "Issue", "Severity", "Solution", "Fix", "Status"):
            tree.heading(col, text=col, command=lambda _col=col: sort_treeview(tree, _col, False))


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
            fix_type = tree.item(selected_item, 'values')[-2]
            if fix_type == "Manual Intervention Required":
                return
            self.fix_selected_file(tree)

        tree.bind("<Double-1>", on_double_click)

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
                      
    def fix_selected_file(self, tree):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a file to fix.")
            return

        selected_item = selected_item[0]
        # Assuming `finding_id` is the first column in the TreeView data
        finding_id, file, primitive, issue, severity, solution, fix_type, status = tree.item(selected_item, 'values')

        if solution == "Manual Intervention Required":
            messagebox.showwarning(
                "Manual Intervention Required",
                f"The issue in {file} with {primitive} requires manual intervention."
            )
            return

        # Pass all required arguments, including finding_id
        self.show_fix_modal(finding_id, file, primitive, issue)

    def show_fix_modal(self, finding_id, file, primitive, issue):
        modal = tk.Toplevel(self.root)
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
                    self.db_manager.update_finding_status(finding_id, 'fixed')

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