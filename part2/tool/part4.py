# main.py
import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
from fix_engine import analyze_and_fix
from tkinter.simpledialog import askstring
from tkinter import simpledialog
from tkinter import Toplevel, StringVar, Listbox, Button, END

# Define algorithm alternatives
algorithm_alternatives = {
    "MD5": ["SHA-256"],
    "SHA-1": ["SHA-256"],
    "AES.MODE_ECB": ["AES.MODE_GCM"],
    "bcrypt.gensalt(rounds=4)": ["bcrypt.gensalt(rounds=12)"],
    "SSLv3": ["TLSv1.3"],
    "TLSv1.0": ["TLSv1.3"],
    "RSA 1024": ["RSA 3072"],
    # Add more as needed
}

# Initialize SQLite databases
def initialize_databases():
    conn = sqlite3.connect("file_versions.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            original_content TEXT,
            modified_content TEXT,
            applied_fix TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Load vulnerabilities from database
def load_vulnerabilities():
    conn = sqlite3.connect("crypto_findings.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, file, primitive, issue, severity, suggestion FROM findings")
    rows = cursor.fetchall()
    conn.close()
    vulnerabilities = []
    for row in rows:
        vulnerabilities.append({
            "ID": row[0],
            "File": row[1],
            "Primitive": row[2],
            "Issue": row[3],
            "Severity": row[4],
            "Suggestion": row[5],
            "Fix Status": "Pending",
            "Applied Fix": None,
        })
    return vulnerabilities

# Apply fixes to files and track versions
def apply_fix(file_path, primitive):
    try:
        original_content, modified_content = analyze_and_fix(file_path)
        if modified_content is None:
            print(f"No fixes applied to {file_path}.")
            return False

        # Write the modified content back to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(modified_content)

        # Log the version
        conn = sqlite3.connect("file_versions.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO file_versions (file_path, original_content, modified_content, applied_fix) VALUES (?, ?, ?, ?)",
            (file_path, original_content, modified_content, primitive)
        )
        conn.commit()
        conn.close()

        print(f"Fix successfully applied to {file_path}.")
        return True
    except Exception as e:
        print(f"Error applying fix to {file_path}: {e}")
        return False

# GUI Application Class
class CryptoFixerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Agility Simulator")
        self.root.geometry("1200x700")

        self.vulnerabilities = []

        self.setup_ui()
        initialize_databases()
        self.load_vulnerabilities()

    def setup_ui(self):
        search_frame = tk.Frame(self.root)
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        search_label = tk.Label(search_frame, text="Search:", font=("Arial", 12))
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, font=("Arial", 12))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        search_entry.bind("<KeyRelease>", self.filter_vulnerabilities)
        # Treeview for vulnerabilities
        self.tree = ttk.Treeview(
            self.root, columns=("ID", "File", "Primitive", "Issue", "Severity", "Fix Status", "Applied Fix"), show='headings'
        )
        self.tree.heading("ID", text="ID", command=lambda c="ID": self.sort_column(c))
        self.tree.heading("File", text="File", command=lambda c="File": self.sort_column(c))
        self.tree.heading("Primitive", text="Primitive", command=lambda c="Primitive": self.sort_column(c))
        self.tree.heading("Issue", text="Issue", command=lambda c="Issue": self.sort_column(c))
        self.tree.heading("Severity", text="Severity", command=lambda c="Severity": self.sort_column(c))
        self.tree.heading("Fix Status", text="Fix Status", command=lambda c="Fix Status": self.sort_column(c))
        self.tree.heading("Applied Fix", text="Applied Fix", command=lambda c="Applied Fix": self.sort_column(c))


        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)

        # Severity Coloring
        self.tree.tag_configure("Critical", background="#FFCCCC")
        self.tree.tag_configure("High", background="#FFD580")
        self.tree.tag_configure("Medium", background="#FFFFCC")
        self.tree.tag_configure("Low", background="#CCFFCC")

        # Action Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        fix_all_button = tk.Button(button_frame, text="Apply Fixes to All", command=self.apply_all_fixes)
        fix_all_button.grid(row=0, column=0, padx=10)

        fix_individual_button = tk.Button(button_frame, text="Fix Selected File", command=self.apply_selected_fix)
        fix_individual_button.grid(row=0, column=1, padx=10)

    def load_vulnerabilities(self):
        self.vulnerabilities = load_vulnerabilities()
        for vuln in self.vulnerabilities:
            alternatives = algorithm_alternatives.get(vuln["Primitive"], [])
            if not alternatives:
                vuln["Fix Status"] = "Manual Intervention Required"
        self.populate_tree()

    def populate_tree(self, vulnerabilities=None):
        if vulnerabilities is None:
            vulnerabilities = self.vulnerabilities

        for item in self.tree.get_children():
            self.tree.delete(item)

        for vuln in vulnerabilities:
            tag = vuln["Severity"] if vuln["Severity"] in ["Critical", "High", "Medium", "Low"] else ""
            self.tree.insert(
                "",
                tk.END,
                values=(
                    vuln["ID"], vuln["File"], vuln["Primitive"], vuln["Issue"], vuln["Severity"], vuln["Fix Status"], vuln["Applied Fix"]
                ),
                tags=(tag,),
            )



    def apply_all_fixes(self):
        for vuln in self.vulnerabilities:
            if vuln["Fix Status"] != "Manual Intervention Required":
                file_path = vuln["File"]
                primitive = vuln["Primitive"]
                success = apply_fix(file_path, primitive)
                vuln["Fix Status"] = "Fixed" if success else "Failed"

        self.populate_tree()
        messagebox.showinfo("Fixes Applied", "Fixes have been applied where possible.")


    def apply_selected_fix(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a file to fix.")
            return

        item = self.tree.item(selected_item[0])
        values = item["values"]

        vuln_id = int(values[0]) - 1  # Map ID to index in `self.vulnerabilities`
        file_path = values[1]
        primitive = values[2]
        status = values[5]

        if status == "Manual Intervention Required":
            messagebox.showwarning("Manual Fix Required", "This file requires manual intervention and cannot be fixed automatically.")
            return

        # Get available alternatives for the primitive
        alternatives = algorithm_alternatives.get(primitive, [])
        if not alternatives:
            messagebox.showwarning("No Alternatives", "No alternatives available for the selected primitive.")
            return

        # Show dropdown to select fix
        def on_selection():
            selected_fix = fix_var.get()
            if selected_fix:
                success = apply_fix(file_path, selected_fix)
                self.vulnerabilities[vuln_id]["Fix Status"] = "Fixed" if success else "Failed"
                self.vulnerabilities[vuln_id]["Applied Fix"] = selected_fix
                self.populate_tree()
                fix_window.destroy()

        fix_window = Toplevel(self.root)
        fix_window.title("Select Fix")
        fix_window.geometry("400x200")
        fix_var = StringVar(fix_window)
        fix_var.set(alternatives[0])  # Default selection

        label = tk.Label(fix_window, text=f"Choose a fix for {primitive}:")
        label.pack(pady=10)

        dropdown = ttk.Combobox(fix_window, textvariable=fix_var, values=alternatives, state="readonly")
        dropdown.pack(pady=10)

        apply_button = Button(fix_window, text="Apply Fix", command=on_selection)
        apply_button.pack(pady=10)

    def sort_column(self, col):
        self.vulnerabilities.sort(key=lambda x: x[col], reverse=not getattr(self, "_sort_asc", True))
        self._sort_asc = not getattr(self, "_sort_asc", True)
        self.populate_tree(self.vulnerabilities)

    def filter_vulnerabilities(self, event=None):
        search_term = self.search_var.get().lower()
        filtered_vulns = [
            vuln for vuln in self.vulnerabilities
            if search_term in str(vuln["File"]).lower() or search_term in str(vuln["Issue"]).lower()
        ]
        self.populate_tree(filtered_vulns)

# Main Function
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoFixerApp(root)
    root.mainloop()
