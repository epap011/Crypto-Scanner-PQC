import tkinter as tk

class DatabaseManagementPage:
    def __init__(self, parent, db_manager):
        self.parent     = parent
        self.db_manager = db_manager

    def show(self):
        tk.Label(
            self.parent,
            text="Database Management? hahaha - this is under Construction..",
            font=("Courier", 16),
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=20)