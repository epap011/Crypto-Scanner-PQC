import tkinter as tk

class HelpPage:
    def __init__(self, parent_frame):
        """
        Initializes the home page.

        :param parent_frame: The parent frame where the home page will be displayed.
        """
        self.parent_frame = parent_frame
        self.photo = None

    def show(self):
        tool_guide  = "1. Each scan generates a detailed review of the case.\n\n" 
        tool_guide += "2. If you want to keep this review for future reference, make sure to save it explicitly.\n\n"
        tool_guide += "3. Every scan corresponds to a new case, and you can view all your saved cases in the 'Manage Cases' section.\n\n"
        tool_guide += "4. Use the 'DB Manager' section to organize or modify your saved cases.\n\n"
        tool_guide += "5. To start a new scan, click on 'New Case'.\n\n"
        tool_guide += "6. If you need assistance, click on 'Help'."


        tk.Label(
            self.parent_frame,
            text=tool_guide,
            font=("Courier", 12),
            justify=tk.LEFT,
            anchor=tk.W,
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=20)

        tk.Label(
            self.parent_frame,
            text="Authors: Nick Giovanopoulos, Efthimis Papageorgiou",
            font=("Courier", 14),
            fg="#00FF41",
            bg="#2E2E2E",
        ).pack(pady=20)
