import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from gui.database_management_page import DatabaseManagementPage
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import ast
import astor
from core.logic import CryptoFixer


class ManageCasesPage:
    def __init__(self, parent, db_manager):
        self.parent     = parent
        self.db_manager = db_manager
        self.fixer      = CryptoFixer()
        self.auto_fix_count = 0
        self.manual_fix_count = 0
        
    def show(self):
        canvas = tk.Canvas(self.parent, bg="#3A3A3A")
        scrollable_frame = ttk.Frame(canvas)

        scrollbar = ttk.Scrollbar(self.parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((10, 75), window=scrollable_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        scrollable_frame.bind("<Configure>", on_frame_configure)

        cases = self.db_manager.get_cases()

        for case in cases:
            case_frame = tk.Frame(scrollable_frame, bg="#3A3A3A", highlightbackground="#FFFFFF", highlightthickness=1)
            case_frame.pack(fill="x", padx=0, pady=0, anchor="center")

            self.case_title = tk.Label(
                case_frame,
                text="Case: " + case[1],
                font=("Courier", 14, 'bold'),
                fg="#FFFFFF",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            self.case_title.pack(fill="x", pady=5)

            case_description = tk.Label(
                case_frame,
                text="file path: " + case[2],
                font=("Courier", 12),
                fg="#D3D3D3",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_description.pack(fill="x", pady=5)

            case_info = tk.Label(
                case_frame,
                text="created at: " + case[3],
                font=("Courier", 12),
                fg="#D3D3D3",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_info.pack(fill="x", pady=5)

            button_frame = tk.Frame(case_frame, bg="#3A3A3A")
            button_frame.pack(pady=10)
            
            delete_button = tk.Button(
                button_frame,
                text="Delete Case",
                font=("Courier", 12),
                fg="#FFFFFF",
                bg="#FF0000",
                command=lambda case_id=case[0]: self.delete_case(case_id),
            )
            delete_button.grid(row=0, column=0, padx=10)

            load_button = tk.Button(
                button_frame,
                text="Load Case",
                font=("Courier", 12),
                fg="#FFFFFF",
                bg="#008000",
                command=lambda case_id=case[0]: self.load_case(case_id),
            )
            load_button.grid(row=0, column=1, padx=10)

    def delete_case(self, case_id):
        confirm = messagebox.askyesno(
            "Confirm Clear",
            "Are you sure you want to delete this case? This action cannot be undone."
        )
        if confirm:
            self.db_manager.delete_case(case_id)
            for widget in self.parent.winfo_children():
                widget.destroy()
            self.show()
            messagebox.showinfo("Success", "Database cleared successfully!")

    def load_case(self, case_id):
        print(f"Loading case with ID: {case_id}")

        case_metadata, findings = self.db_manager.fetch_case(case_id)


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
            self.critical_count = sum(1 for row in filtered_rows if row[4] == 'Critical')
            self.high_count     = sum(1 for row in filtered_rows if row[4] == 'High')
            self.medium_count   = sum(1 for row in filtered_rows if row[4] == 'Medium')
            self.low_count      = sum(1 for row in filtered_rows if row[4] == 'Low')

            ### RSA related statistics
            self.rsa_related_count = sum(1 for row in filtered_rows if row[2] == 'RSA')

            ### ECC related statistics
            self.ecc_related_count = sum(1 for row in filtered_rows if row[2] == 'ECC')

            ### AES related statistics
            self.aes_related_count = sum(1 for row in filtered_rows if row[2] == 'AES')

            ### DES related statistics
            self.des_related_count = sum(1 for row in filtered_rows if row[2] == 'DES')

            ### MD5 related statistics
            self.md5_related_count = sum(1 for row in filtered_rows if row[2] == 'MD5')

            ### SHA-1 related statistics
            self.sha1_related_count = sum(1 for row in filtered_rows if row[2] == 'SHA-1')

            ### SHA-256 related statistics
            self.sha256_related_count = sum(1 for row in filtered_rows if row[2] == 'SHA-256')

            ### TLS related statistics
            self.tls_related_count = sum(1 for row in filtered_rows if row[2] == 'TLS')
        
        self.parent_panel = tk.Toplevel(self.parent)
        self.parent_panel.title("Case: " + case_metadata[1])
        self.parent_panel.geometry("1280x700")

        self.statistics_panel = tk.Frame(self.parent_panel, bg="#3D3D3D")
        self.statistics_panel.pack(fill=tk.X, padx=0, pady=5)
        
        search_frame = tk.Frame(self.parent_panel, bg="#3D3D3D")
        search_frame.pack(fill=tk.X, padx=250, pady=5)

        search_label = tk.Label(search_frame, text="Search:", font=("Courier", 12), fg="white", bg="#2E2E2E")
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        search_entry = tk.Entry(search_frame, font=("Courier", 12))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        search_entry.bind("<KeyRelease>", search_results)

        tree = ttk.Treeview(
            self.parent_panel,
            columns=("ID","File", "Primitive", "Issue", "Severity", "Solution", "Fix", "Mosca Urgent", "Quantum Vulnerable", "Status"),
            show='headings'
        )
        tree.pack(fill=tk.BOTH, expand=True)
        for col in ("ID","File", "Primitive", "Issue", "Severity", "Solution", "Fix", "Mosca Urgent", "Quantum Vulnerable", "Status"):
            tree.heading(col, text=col, command=lambda _col=col: sort_treeview(tree, _col, False))
        tree.pack(fill=tk.BOTH, expand=True)

        tree.column("ID", width=0, stretch=tk.NO)
        tree.tag_configure('Critical', background='#FFCCCC')
        tree.tag_configure('High'    , background='#FFD580')
        tree.tag_configure('Medium'  , background='#FFFFCC')
        tree.tag_configure('Low'     , background='#CCFFCC')

        rows = []

        def debug_sample_data(data):
            print("Sample Data:")
            for i, item in enumerate(data):
                print(f"Index {i}: {item}")

        if findings:
            print("Debugging a sample finding:")
            debug_sample_data(findings[0])
        for finding in findings:
            rows += [(finding[0], finding[2], finding[3], finding[4], finding[5], finding[6], finding[7], finding[8], finding[9], finding[10])]

        self.populate_tree(tree, rows)
        update_statistics(rows)
        self.show_statistic_pies()

        def on_double_click(event):
            selected_item = tree.selection()
            if not selected_item:
                return
            selected_item = selected_item[0]
            fix_type = tree.item(selected_item, 'values')[7]
            if fix_type == "Manual Intervention Required":
                return
            self.fix_selected_file(tree, tree.item(selected_item, 'values')[0])

        tree.bind("<Double-1>", on_double_click)

    def populate_tree(self, treeview, data):
        for item in treeview.get_children():
            treeview.delete(item)
        for row in data:
            finding_id = row[0]
            file_path = row[1]
            primitive = row[2]
            issue     = row[4]
            severity  = row[5]
            solution  = row[6]
            fix_type  = row[6]
            mosca_urgent = row[7]
            quantum_vulnerable = row[8]           
            status = row[9]        
            
            fix_options = self.fixer.get_fix_options(primitive)
            if fix_options and fix_options != ["Manual Intervention Required"]:
                fix_type = "Automatic fix exists"
                self.auto_fix_count += 1
            else:
                fix_type = "Manual Intervention Required"
                self.manual_fix_count += 1

            if mosca_urgent == 1:
                mosca_urgent = "True"
            else:
                mosca_urgent = "False"
            
            if quantum_vulnerable == 1:
                quantum_vulnerable = "True"
            else:
                quantum_vulnerable = "False"
            tag = severity
            treeview.insert("", tk.END, values=(finding_id, file_path, primitive, issue, severity, solution, fix_type, mosca_urgent, quantum_vulnerable, status), tags=(tag,))
        #treeview.tag_configure('Critical', background='#FFCCCC')

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

    def fix_selected_file(self, tree, finding_id):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a file to fix.")
            return

        selected_item = selected_item[0]

        finding_id, file, primitive, issue, severity, solution, fix, mosca_urgent, quantum_vulnerable, status = tree.item(selected_item, 'values')

        if fix == "Manual Intervention Required":
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