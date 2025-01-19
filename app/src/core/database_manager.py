# DatabaseManager.py
import sqlite3
import csv
from tkinter import filedialog, messagebox
import datetime
import os

class DatabaseManager:
    def __init__(self, db_name="crypto_findings.db"):
        path = "../data/databases/"
        now = datetime.datetime.now()
        date = now.strftime("%Y-%m-%d")
        hour = now.strftime("%H-%M-%S")
        db_name = date + "-" + hour + "-" + db_name
        self.db_name = path + db_name

        if not os.path.exists(path):
            os.makedirs(path)

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
                status TEXT DEFAULT 'not_fixed',
                UNIQUE(file, primitive, parameters)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fix_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER,
                original_code TEXT,
                file TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)
        conn.commit()
        conn.close()

    def save_findings(self, findings):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        for finding in findings:
            parameters = finding['parameters'] if finding['parameters'] else ""
            try:
                # Insert the finding into the findings table
                cursor.execute("""
                    INSERT OR IGNORE INTO findings 
                    (file, primitive, parameters, issue, severity, suggestion, quantum_vulnerable, mosca_urgent, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding['file'], finding['primitive'], parameters,
                    finding['issue'], finding['severity'], finding['suggestion'],
                    finding['quantum_vulnerable'], finding['mosca_urgent'], 'not_fixed'
                ))

                # Get the ID of the inserted or existing finding
                cursor.execute("SELECT id FROM findings WHERE file = ? AND primitive = ? AND parameters = ?", 
                            (finding['file'], finding['primitive'], parameters))
                finding_id = cursor.fetchone()[0]

                # Check if the original code is already stored in fix_history
                cursor.execute("SELECT COUNT(*) FROM fix_history WHERE finding_id = ?", (finding_id,))
                if cursor.fetchone()[0] == 0:
                    # Read the original code from the file
                    try:
                        with open(finding['file'], 'r') as f:
                            original_code = f.read()
                        
                        # Insert the original code into the fix_history table
                        cursor.execute("""
                            INSERT INTO fix_history (finding_id, original_code, file)
                            VALUES (?, ?, ?)
                        """, (finding_id, original_code, finding['file']))
                    except FileNotFoundError:
                        logging.warning(f"File not found: {finding['file']}")
                    except Exception as e:
                        logging.error(f"Error reading file {finding['file']}: {e}")

            except sqlite3.IntegrityError:
                logging.warning(f"Duplicate finding detected: {finding}")
        conn.commit()
        conn.close()

    def fetch_all_findings(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, file, primitive, parameters, issue, severity, suggestion, quantum_vulnerable, mosca_urgent, status
            FROM findings
        """)
        rows = cursor.fetchall()
        conn.close()
        return rows

    def save_case_to_txt(self, case):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save Test Case as TXT"
        )
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(case)
            messagebox.showinfo("Save Complete", f"Test case saved to {file_path}.")
    
    def fetch_all_cases(self):
        results = ["Case 1, Case 2, Case 3, Case 4, Case 5, Case 6, Case 7, Case 8, Case 9, Case 10"]
        return results

    def export_findings_to_csv(self):
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
                    "Issue", "Severity", "Suggestion", "Quantum Vulnerable", "Mosca Urgent", "Status"
                ])
                writer.writerows(rows)
            messagebox.showinfo("Export Complete", f"Findings exported to {file_path}.")

    def update_finding_status(self, finding_id, status):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE findings
            SET status = ?
            WHERE id = ?
        """, (status, finding_id))
        conn.commit()
        conn.close()

    def save_fix_history(self, finding_id, original_code, file):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO fix_history (finding_id, original_code, file)
            VALUES (?, ?, ?)
        """, (finding_id, original_code, file))
        conn.commit()
        conn.close()

    def fetch_original_code(self, finding_id):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT original_code FROM fix_history WHERE finding_id = ?
        """, (finding_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
