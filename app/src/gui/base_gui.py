import tkinter as tk
from gui.home_page import HomePage
from gui.navigation import Navigation
from gui.new_case_page import NewCasePage
from gui.manage_cases_page import ManageCasesPage
from gui.database_management_page import DatabaseManagementPage
from gui.help_page import HelpPage

class CryptoScannerApp:
    def __init__(self, root, analyzer, db_manager):
        self.root       = root
        self.analyzer   = analyzer
        self.db_manager = db_manager

        self.root.title("Crypto Scanner")
        self.root.geometry("1280x700")

        self.navigation_panel = tk.Frame(self.root, bg="#1F1F1F", width=300, highlightthickness=2, highlightbackground="green", highlightcolor="green")
        self.navigation_panel.pack(side=tk.LEFT, fill=tk.Y)

        self.page_content = tk.Frame(self.root, bg="#2E2E2E")
        self.page_content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.navigation    = Navigation(self.root, self.navigation_panel, self.page_content)
        self.home_page     = HomePage(self.page_content)
        self.new_case_page = NewCasePage(self.page_content)
        self.show_cases    = ManageCasesPage(self.page_content, self.db_manager)
        self.database_management_page = DatabaseManagementPage(self.page_content, self.db_manager)
        self.help_page     = HelpPage(self.page_content)
        
        self.navigation.add_button("Home"        , self.home_page.show)
        self.navigation.add_button("New Case"    , self.new_case_page.show)
        self.navigation.add_button("Manage Cases", self.show_cases.show)
        self.navigation.add_button("DB Manager"  , self.database_management_page.show)
        self.navigation.add_button("Help"        , self.help_page.show)

        self.last_width  = self.root.winfo_width()
        self.last_height = self.root.winfo_height()

        self.navigation.activate_button("Home")
        
        #self.root.bind("<Configure>", self.on_resize)
    
    #resize event is broken
    def on_resize(self, event):
        current_width  = event.width
        current_height = event.height

        if current_width != self.last_width or current_height != self.last_height:
            #print(f"Window resized to {current_width}x{current_height}")
            self.last_width  = current_width
            self.last_height = current_height
            #self.home_page.display_image()
