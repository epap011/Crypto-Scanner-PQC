import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class ShowCases:
    def __init__(self, parent, db_manager):
        self.parent     = parent
        self.db_manager = db_manager

    def show(self):
        canvas = tk.Canvas(self.parent, bg="#3A3A3A")
        scrollable_frame = ttk.Frame(canvas)

        scrollbar = ttk.Scrollbar(self.parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((10, 75), window=scrollable_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        scrollable_frame.bind("<Configure>", on_frame_configure)

        cases = self.db_manager.get_cases()

        for case in cases:
            case_frame = tk.Frame(scrollable_frame, bg="#3A3A3A", highlightbackground="#FFFFFF", highlightthickness=1)
            case_frame.pack(fill="x", padx=0, pady=0, anchor="center")

            case_title = tk.Label(
                case_frame,
                text="Case: " + case[1],
                font=("Courier", 14, 'bold'),
                fg="#FFFFFF",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_title.pack(fill="x", pady=5)

            case_description = tk.Label(
                case_frame,
                text="file path: " + case[2],
                font=("Courier", 12),
                fg="#D3D3D3",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_description.pack(fill="x", pady=5)

            case_info = tk.Label(
                case_frame,
                text="created at: " + case[3],
                font=("Courier", 12),
                fg="#D3D3D3",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_info.pack(fill="x", pady=5)

            button_frame = tk.Frame(case_frame, bg="#3A3A3A")
            button_frame.pack(pady=10)
            
            delete_button = tk.Button(
                button_frame,
                text="Delete Case",
                font=("Courier", 12),
                fg="#FFFFFF",
                bg="#FF0000",
                command=lambda case_id=case[0]: self.delete_case(case_id),
            )
            delete_button.grid(row=0, column=0, padx=10)

            load_button = tk.Button(
                button_frame,
                text="Load Case",
                font=("Courier", 12),
                fg="#FFFFFF",
                bg="#008000",
                command=lambda case_id=case[0]: self.load_case(case_id),
            )
            load_button.grid(row=0, column=1, padx=10)

    def delete_case(self, case_id):
        confirm = messagebox.askyesno(
            "Confirm Clear",
            "Are you sure you want to delete this case? This action cannot be undone."
        )
        if confirm:
            self.db_manager.delete_case(case_id)
            for widget in self.parent.winfo_children():
                widget.destroy()
            self.show()
            messagebox.showinfo("Success", "Database cleared successfully!")

    def load_case(self, case_id):
        messagebox.showinfo("Under Construction", "This feature is under construction.")