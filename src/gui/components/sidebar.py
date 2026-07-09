import customtkinter as ctk


class Sidebar(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(
            parent,
            width=220,
            fg_color="#202020"
        )

        self.pack_propagate(False)

        # =====================================================
        # TITLE
        # =====================================================

        title = ctk.CTkLabel(
            self,
            text="SecureWin Toolkit",
            font=("Segoe UI", 20, "bold")
        )

        title.pack(
            pady=(20, 30)
        )

        # =====================================================
        # DASHBOARD
        # =====================================================

        self.dashboard_btn = ctk.CTkButton(
            self,
            text="🏠 Dashboard",
            height=40,
            fg_color="#5A0000",
            hover_color="#7A0000",
            command=parent.show_dashboard
        )

        self.dashboard_btn.pack(
            fill="x",
            padx=15,
            pady=8
        )

        # =====================================================
        # WINDOWS AUDIT
        # =====================================================

        self.audit_btn = ctk.CTkButton(
            self,
            text="🛡 Windows Audit",
            height=40,
            fg_color="#5A0000",
            hover_color="#7A0000",
            command=parent.show_windows_audit
        )

        self.audit_btn.pack(
            fill="x",
            padx=15,
            pady=8
        )

        # =====================================================
        # NETWORK AUDIT
        # =====================================================

        self.network_btn = ctk.CTkButton(
            self,
            text="🌐 Network Audit",
            height=40,
            fg_color="#5A0000",
            hover_color="#7A0000",
            command=parent.show_network_audit
        )

        self.network_btn.pack(
            fill="x",
            padx=15,
            pady=8
        )

        # =====================================================
        # REPORTS
        # =====================================================

        self.reports_btn = ctk.CTkButton(
            self,
            text="📄 Reports",
            height=40,
            fg_color="#5A0000",
            hover_color="#7A0000"
        )

        self.reports_btn.pack(
            fill="x",
            padx=15,
            pady=8
        )

        # =====================================================
        # SETTINGS
        # =====================================================

        self.settings_btn = ctk.CTkButton(
            self,
            text="⚙ Settings",
            height=40,
            fg_color="#5A0000",
            hover_color="#7A0000"
        )

        self.settings_btn.pack(
            fill="x",
            padx=15,
            pady=8
        )