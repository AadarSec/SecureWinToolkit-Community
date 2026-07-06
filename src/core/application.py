from src.gui.main_window import MainWindow
import customtkinter as ctk


class SecureWinApplication:
    def __init__(self):
        # Set application theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Create main window
        self.window = ctk.CTk()
        self.window.title("SecureWin Toolkit")
        self.window.geometry("1200x700")
        self.window.minsize(1000, 600)
        self.main_window = MainWindow(self.window)

    def run(self):
        self.window.mainloop()