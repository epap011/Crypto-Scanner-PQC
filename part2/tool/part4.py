# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
from logic import CryptoFixer 

class CryptoFixerGUI:
    def __init__(self, root, fixer):
        self.root = root
        self.fixer = fixer

        self.setup_ui()

    def setup_ui(self):
        self.root.title("Cryptographic Fixer")
        self.root.geometry("800x600")

        self.tree = ttk.Treeview(
            self.root, columns=("File", "Primitive", "Issue", "Severity", "Fixable"), show='headings'
        )
        self.tree.heading("File", text="File")
        self.tree.heading("Primitive", text="Primitive")
        self.tree.heading("Issue", text="Issue")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("Fixable", text="Fixable")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<Double-1>", self.on_item_double_click)

        fix_button = tk.Button(
            self.root, text="Fix Selected File", command=self.fix_selected_file
        )
        fix_button.pack(pady=10)

        self.load_findings()

    def load_findings(self):
        findings = self.fixer.fetch_findings()
        for finding in findings:
            file, primitive, issue, severity = finding[1], finding[2], finding[4], finding[5]
            # Determine fixability
            fixable = "Yes" if "Manual Fix Required" not in self.fixer.get_fix_options(primitive) else "No"
            self.tree.insert("", tk.END, values=(file, primitive, issue, severity, fixable))

    def fix_selected_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a file to fix.")
            return

        selected_item = selected_item[0]
        file, primitive, issue, severity, fixable = self.tree.item(selected_item, 'values')

        if fixable == "No":
            messagebox.showwarning(
                "Manual Intervention Required", 
                f"The issue in {file} with {primitive} requires manual intervention."
            )
            return

        # If fixable, proceed to show the fix modal
        self.show_fix_modal(file, primitive, issue)


    def on_item_double_click(self, event):
        selected_item = self.tree.selection()[0]
        file, primitive, issue, severity, fixable = self.tree.item(selected_item, 'values')

        if fixable == "No":
            messagebox.showwarning(
                "Manual Intervention Required", 
                f"The issue in {file} with {primitive} requires manual intervention."
            )
            return

        # If fixable, proceed to show the fix modal
        self.show_fix_modal(file, primitive, issue)


    def show_fix_modal(self, file, primitive, issue):
        modal = tk.Toplevel(self.root)
        modal.title("Fix Cryptographic Issue")
        modal.geometry("400x300")

        tk.Label(modal, text=f"File: {file}").pack(pady=5)
        tk.Label(modal, text=f"Primitive: {primitive}").pack(pady=5)
        tk.Label(modal, text=f"Issue: {issue}").pack(pady=5)

        tk.Label(modal, text="Select Fix:").pack(pady=10)
        fixes = self.fixer.get_fix_options(primitive)

        selected_fix = tk.StringVar()
        dropdown = ttk.Combobox(modal, values=fixes, textvariable=selected_fix)
        dropdown.pack(pady=10)

        def apply_fix():
            fix = selected_fix.get()
            if not fix:
                messagebox.showerror("Error", "Please select a fix.")
                return

            changes = self.fixer.generate_ast_changes(primitive, fix)
            if changes:
                result = self.fixer.apply_fix(file, changes)
                if result is True:
                    messagebox.showinfo("Success", f"Fix applied to {file}.")
                    modal.destroy()
                else:
                    messagebox.showerror("Error", result)
            else:
                messagebox.showwarning("Warning", "No automated fix available. Manual intervention required.")

        tk.Button(modal, text="Apply Fix", command=apply_fix).pack(pady=20)

if __name__ == "__main__":
    fixer = CryptoFixer()
    root = tk.Tk()
    app = CryptoFixerGUI(root, fixer)
    root.mainloop()
