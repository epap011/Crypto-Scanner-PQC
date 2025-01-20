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
        tool_guide  = "1. Every time you run a scan, the tool will generate a report which can be saved for later reference.\n\n"
        tool_guide += "2. Each scan you do is a different case, and you can view all your cases in the 'Show Cases' section.\n\n"
        tool_guide += "3. You can also manage your cases in the 'DB Manager' section.\n\n"
        tool_guide += "4. If you want to start a new scan, click on 'New Case'.\n\n"
        tool_guide += "5. If you need help, click on 'Home' to come back to this page."

        tk.Label(
            self.parent_frame,
            text=tool_guide,
            font=("Courier", 12),
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=20)
