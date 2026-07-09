import customtkinter as ctk

from src.gui.components.sidebar import Sidebar
from src.gui.pages.dashboard import Dashboard
from src.gui.pages.windows_audit import WindowsAudit
from src.gui.pages.network_audit import NetworkAudit


class MainWindow(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent)

        self.pack(fill="both", expand=True)

        # Sidebar
        self.sidebar = Sidebar(self)
        self.sidebar.pack(side="left", fill="y")

        # Content Area
        self.content = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.content.pack(
            side="right",
            fill="both",
            expand=True
        )

        # Pages
        self.dashboard = Dashboard(self.content)

        self.audit_page = WindowsAudit(self.content)

        self.network_audit = NetworkAudit(self.content)

        # Default Page
        self.dashboard.pack(
            fill="both",
            expand=True
        )

    # =====================================================
    # DASHBOARD
    # =====================================================

    def show_dashboard(self):

        self.audit_page.pack_forget()

        self.network_audit.pack_forget()

        self.dashboard.pack(
            fill="both",
            expand=True
        )

    # =====================================================
    # WINDOWS AUDIT
    # =====================================================

    def show_windows_audit(self):

        self.dashboard.pack_forget()

        self.network_audit.pack_forget()

        self.audit_page.pack(
            fill="both",
            expand=True
        )

    # =====================================================
    # NETWORK AUDIT
    # =====================================================

    def show_network_audit(self):

        self.dashboard.pack_forget()

        self.audit_page.pack_forget()

        self.network_audit.pack(
            fill="both",
            expand=True
        )