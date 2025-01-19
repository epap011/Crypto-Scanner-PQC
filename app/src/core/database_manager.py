# DatabaseManager.py
import sqlite3
import csv
from tkinter import filedialog, messagebox
import datetime
import os
import logging

class DatabaseManager:
    def __init__(self, db_name="case_database.db"):        
        path = "../data/databases/"
        self.db_name = os.path.join(path, db_name)

        if not os.path.exists(path):
            os.makedirs(path)

        if os.path.exists(self.db_name):
            return

        self.initialize_database()

    def initialize_database(self):
        conn   = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                folder_path TEXT,
                created_at TEXT
            )
        """)
    
        conn.commit()
        conn.close()

    def store_case(self, folder_path, findings, case_name=None):
        """
        Save scan results to the database, associating them with a specific case.

        :param folder_path: Path to the scanned folder.
        :param findings: List of findings to save.
        :param case_name: Optional case name. If not provided, a unique name will be generated.
        """
        print("folder_path", folder_path)
        print("case_name", case_name)
        if case_name is None:
            now = datetime.datetime.now()
            case_name = f"case_{now.strftime('%Y%m%d_%H%M%S')}"

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Ensure the cases metadata table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                folder_path TEXT,
                created_at TEXT
            )
        """)

        # Insert or update the case metadata
        cursor.execute("""
            INSERT OR IGNORE INTO cases (name, folder_path, created_at)
            VALUES (?, ?, ?)
        """, (case_name, folder_path, datetime.datetime.now()))

        # Retrieve the case_id for foreign key reference
        cursor.execute("SELECT id FROM cases WHERE name = ?", (case_name,))
        case_id = cursor.fetchone()[0]

        # Ensure the unified findings table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                file TEXT,
                primitive TEXT,
                parameters TEXT,
                issue TEXT,
                severity TEXT,
                suggestion TEXT,
                quantum_vulnerable BOOLEAN,
                mosca_urgent BOOLEAN,
                status TEXT DEFAULT 'not_fixed',
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        """)

        # Save findings associated with this case
        for finding in findings:
            parameters = finding.get('parameters', "")
            try:
                cursor.execute("""
                    INSERT INTO findings 
                    (case_id, file, primitive, parameters, issue, severity, suggestion, quantum_vulnerable, mosca_urgent, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    case_id, finding['file'], finding['primitive'], parameters,
                    finding['issue'], finding['severity'], finding['suggestion'],
                    finding['quantum_vulnerable'], finding['mosca_urgent'], 'not_fixed'
                ))
            except sqlite3.IntegrityError:
                logging.warning(f"Duplicate finding detected: {finding}")

        conn.commit()
        conn.close()

        logging.info(f"Scan results saved under case: {case_name}")

    def get_cases(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases")
        rows = cursor.fetchall()
        conn.close()
        return rows

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

    def clear_database(self):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS cases")
            cursor.execute("DROP TABLE IF EXISTS findings")
            cursor.execute("DROP TABLE IF EXISTS fix_history")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    folder_path TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()
            print("Database contents cleared successfully.")
        except sqlite3.Error as e:
            print(f"Error clearing database contents: {e}")
        finally:
            conn.close()
    
    def export_database(self, file_path):
        try:
            with open(self.db_name, 'rb') as source:
                with open(file_path, 'wb') as dest:
                    dest.write(source.read())
            print(f"Database exported to {file_path}")
        except Exception as e:
            print(f"Error exporting database: {e}")