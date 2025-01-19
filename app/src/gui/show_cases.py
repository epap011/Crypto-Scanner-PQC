import tkinter as tk

class ShowCases:
    def __init__(self, parent, db_manager):
        self.parent     = parent
        self.db_manager = db_manager

    def show(self):
        title_label = tk.Label(
            self.parent,
            text="Show Cases? hahaha - This is under Construction..",
            font=("Courier", 16, 'bold'),
            fg="#FFFFFF",
            bg="#2E2E2E",
        )
        title_label.pack(pady=20)

        cases = self.db_manager.get_cases()
        print(cases)

        for case in cases:
            case_frame = tk.Frame(self.parent, bg="#3A3A3A", relief="solid", borderwidth=1)
            case_frame.pack(fill="x", padx=10, pady=10, anchor="w")

            case_title = tk.Label(
                case_frame,
                text=case[1],
                font=("Courier", 14, 'bold'),
                fg="#FFFFFF",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_title.pack(fill="x", pady=5)

            case_description = tk.Label(
                case_frame,
                text="path: " + case[2],
                font=("Courier", 12),
                fg="#D3D3D3",
                bg="#3A3A3A",
                anchor="w",
                padx=10,
            )
            case_description.pack(fill="x", pady=5)

            # Adding additional information (e.g., case type)
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

            delete_button = tk.Button(
                case_frame,
                text="Delete Case",
                font=("Courier", 12),
                fg="#FFFFFF",
                bg="#FF0000",
                command=lambda case_id=case[0]: self.delete_case(case_id),
            )
            delete_button.pack(pady=10)

            load_button = tk.Button(
                case_frame,
                text="Load Case",
                font=("Courier", 12),
                fg="#FFFFFF",
                bg="#008000",
                command=lambda case_id=case[0]: self.load_case(case_id),
            )
            load_button.pack(pady=10)