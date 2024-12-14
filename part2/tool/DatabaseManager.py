#DatabaseManager.py
import sqlite3
import csv
from tkinter import filedialog, messagebox

class DatabaseManager:
    def __init__(self, db_name="crypto_findings.db"):
        self.db_name = db_name
        self.initialize_database()

    def initialize_database(self):
        conn = sqlite3.connect(self.db_name)
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
                UNIQUE(file, primitive, parameters)
            )
        """)
        conn.commit()
        conn.close()

    def save_findings(self, findings):
        conn = sqlite3.connect(self.db_name)
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

    def fetch_all_findings(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings")
        rows = cursor.fetchall()
        conn.close()
        return rows

    def export_findings_to_csv(self):
        """Export all findings to a CSV file."""
        conn = sqlite3.connect(self.db_name)
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