import tkinter as tk
from PIL import Image, ImageTk

class HomePage:
    def __init__(self, parent_frame):
        """
        Initializes the home page.

        :param parent_frame: The parent frame where the home page will be displayed.
        """
        self.parent_frame = parent_frame
        self.photo = None

    def show(self):
        """
        Displays the home page in the parent frame.
        """
        self.clear_main_content()

        self.text_frame = tk.Frame(self.parent_frame, bg="#2E2E2E")
        self.text_frame.pack(side=tk.TOP)

        self.image_frame = tk.Frame(self.parent_frame, bg="#2E2E2E")
        self.image_frame.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM)

        tk.Label(
            self.text_frame,
            text="Welcome to Crypto Scanner",
            font=("Courier", 18, "bold"),
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=50)

        tk.Label(
            self.text_frame,
            text="This tool helps you identify and fix cryptographic issues in your Python code.",
            font=("Courier", 12),
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=20)

        tk.Label(
            self.text_frame,
            text="Use the navigation panel on the left to get started.",
            font=("Courier", 12),
            fg="white",
            bg="#2E2E2E",
        ).pack(pady=10)

        self.display_image("../data/assets/synth.png")

    def clear_main_content(self):
        """
        Clears all widgets in the parent frame.
        """
        for widget in self.parent_frame.winfo_children():
            widget.destroy()

    def display_image(self, image_path):
        """
        Attempts to load and display an image on the home page.

        :param image_path: Path to the image file.
        """

        try:
            self.image_frame.update_idletasks()
            frame_width  = self.image_frame.winfo_width()
            frame_height = self.image_frame.winfo_height()

            image = Image.open(image_path)
            
            image = image.resize((frame_width, frame_height))
            
            self.photo = ImageTk.PhotoImage(image)
            image_label = tk.Label(self.image_frame, image=self.photo, bg="#2E2E2E")
            image_label.pack(pady=10)
        except Exception as e:
            tk.Label(
                self.image_frame,
                text=f"Error loading image: {e}",
                font=("Courier", 12),
                fg="red",
                bg="#F5F5F5",
            ).pack(pady=10)
