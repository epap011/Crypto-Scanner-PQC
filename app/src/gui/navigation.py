import tkinter as tk

class Navigation:
    def __init__(self, root, navigation_panel, page_content):
        self.root             = root
        self.navigation_panel = navigation_panel
        self.page_content     = page_content
        self.current          = None
        self.active_button    = None
        self.buttons          = []

        title_label = tk.Label(
            self.navigation_panel,
            text="Crypto Scanner",
            font=("Courier", 20, "bold"),
            fg="white",
            bg="#1F1F1F"
        )
        title_label.pack(pady=20, padx=10)

        #put status online in the bottom of the navigation panel
        status_label = tk.Label(
            self.navigation_panel,
            text="Status: Online",
            font=("Courier", 12),
            fg="#00FF41",
            bg="#1F1F1F"
        )
        status_label.pack(side=tk.BOTTOM, pady=20, padx=10)
    
    def add_button(self, text, command):
        button = tk.Button(
            self.navigation_panel,
            text=text,
            font=("Courier", 12, "bold"),
            fg="white",
            bg="#00B140",
            activebackground="#BF80FF",
            activeforeground="white",
            bd=0,
            relief="flat",
            command=lambda: self.handle_button(button, command)
        )
        button.pack(fill=tk.X, pady=5, padx=10, ipady=10)

        self.buttons.append(button)

    def handle_button(self, button, command):
        self.clear_page_content()
        if self.active_button:
            self.active_button.configure(bg="#00B140")

        button.configure(bg="#9900E6")
        self.active_button = button

        command()
    
    def clear_page_content(self):
        for widget in self.page_content.winfo_children():
            widget.destroy()
        
    def activate_button(self, text):
        for button in self.buttons:
            if button.cget("text") == text:
                button.invoke()
                break