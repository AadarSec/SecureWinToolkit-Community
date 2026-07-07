import customtkinter as ctk


class Sidebar(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(
            parent,
            width=220,
            fg_color="#202020"
        )

        self.pack_propagate(False)

        title = ctk.CTkLabel(
            self,
            text="SecureWin Toolkit",
            font=("Segoe UI", 20, "bold")
        )
        title.pack(pady=(20, 30))

        buttons = [
            "🏠 Dashboard",
            "🛡 Windows Audit",
            "🌐 Network Audit",
            "📄 Reports",
            "⚙ Settings"
        ]

        for text in buttons:
            btn = ctk.CTkButton(
                self,
                text=text,
                height=40,
                fg_color="#5A0000",
                hover_color="#7A0000"
            )
            btn.pack(fill="x", padx=15, pady=8)