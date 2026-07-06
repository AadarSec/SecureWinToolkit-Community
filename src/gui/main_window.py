import customtkinter as ctk


class MainWindow(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)

        self.pack(fill="both", expand=True)

        title = ctk.CTkLabel(
            self,
            text="SecureWin Toolkit",
            font=("Segoe UI", 28, "bold")
        )

        title.pack(pady=30)