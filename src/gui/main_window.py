import customtkinter as ctk

from src.gui.components.sidebar import Sidebar
from src.gui.pages.dashboard import Dashboard
from src.gui.pages.windows_audit import WindowsAudit


class MainWindow(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent)

        self.pack(fill="both", expand=True)

        # Sidebar
        self.sidebar = Sidebar(self)
        self.sidebar.pack(side="left", fill="y")

        # Content Area
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(side="right", fill="both", expand=True)

        # Pages
        self.dashboard = Dashboard(self.content)
        self.audit_page = WindowsAudit(self.content)

        # Show Dashboard by default
        self.dashboard.pack(fill="both", expand=True)

    def show_dashboard(self):

        self.audit_page.pack_forget()

        self.dashboard.pack(
            fill="both",
            expand=True
        )

    def show_windows_audit(self):

        self.dashboard.pack_forget()

        self.audit_page.pack(
            fill="both",
            expand=True
        )