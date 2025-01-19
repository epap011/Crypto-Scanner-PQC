import tkinter as tk
from tkinter import messagebox, filedialog
import os

class DatabaseManagementPage:
    def __init__(self, parent, db_manager):
        self.parent = parent
        self.db_manager = db_manager

    def show(self):
        self.active_db_label = tk.Label(
            self.parent,
            text=f"Active Database: poutses.db",
            font=("Courier", 14),
            fg="white",
            bg="#2E2E2E"
        )
        self.active_db_label.pack(pady=10)

        tk.Label(
            self.parent,
            text="Database Manager: Import/Export/Clear your database here",
            font=("Courier", 16),
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=20)

        button_frame = tk.Frame(self.parent, bg="#2E2E2E")
        button_frame.pack(pady=10)

        clear_button = tk.Button(
            button_frame,
            text="Clear Database",
            command=self.clear_database,
            font=("Courier", 12),
            bg="#FF4D4D",
            fg="white",
            width=15
        )
        clear_button.grid(row=0, column=0, padx=10)

    def clear_database(self):
        confirm = messagebox.askyesno(
            "Confirm Clear",
            "Are you sure you want to clear the database? This action cannot be undone."
        )
        if confirm:
            self.db_manager.clear_database()
            messagebox.showinfo("Success", "Database cleared successfully!")
