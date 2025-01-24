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
        tool_guide = (
            "1. Each scan generates a detailed review of the case.\n\n"
            "2. If you want to keep this review for future reference, make sure to save it explicitly.\n\n"
            "3. Every scan corresponds to a new case, and you can view all your saved cases in the 'Manage Cases' section.\n\n"
            "4. Use the 'DB Manager' section to organize or modify your saved cases.\n\n"
            "5. To start a new scan, click on 'New Case'.\n\n"
            "6. Scan results are displayed in a table format. You can sort findings by clicking on any column header (e.g., Severity, Primitive).\n"
            "Click again to toggle between ascending and descending order.\n\n"
            "7. To fix an issue, double-click on a finding in the table. This will open a pop-up window with the following features:\n"
            "   - The left panel displays the original code from the file.\n"
            "   - The right panel shows a preview of the updated code when you select a fix from the dropdown menu.\n"
            "   - Only findings with 'Automatic fix exists' in the 'Fix' column can be fixed automatically.\n"
            "   - To save the changes, click 'Save Changes'. This updates the file and marks the finding as 'fixed' in the table.\n"
            "   - To revert changes, double-click on the finding again and click 'Revert Changes' in the pop-up window.\n"
            "   - This restores the original code and marks the finding as 'not_fixed'.\n\n"
            "8. The 'Status' column indicates whether a finding has been fixed or not (values: fixed/not_fixed).\n\n"
            "9. The Statistics Panel provides an overview of the findings, including:\n"
            "   - Distribution of severity levels (Critical, High, Medium, Low).\n"
            "   - Summary of findings per cryptographic primitive (e.g., AES, RSA).\n"
            "   - Count of findings that require manual fixes vs. those with automatic fixes.\n\n"
            "10. To save your scan results, click 'Save Case' and provide a name for the case. Saved cases can be accessed later in the 'Manage Cases' section.\n\n"
            "11. If you need assistance, click on 'Help'."
        )

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
