import customtkinter as ctk

from src.gui.components.details_popup import DetailsPopup
from src.core.audit_cache import AuditCache


class NetworkAudit(ctk.CTkFrame):

    # =====================================================
    # CATEGORIES
    # =====================================================

    CATEGORIES = {
        "Network Information": {
            "description":
                "Collects network identity and addressing information.",
            "checks": [
                ("🌐", "Local IP Address"),
                ("🌍", "Public IP Address"),
                ("🖧", "Default Gateway"),
                ("📡", "DNS Servers"),
                ("📦", "DHCP Status"),
                ("🆔", "MAC Address"),
            ]
        },
        "Network Configuration": {
            "description":
                "Reviews adapter configuration and TCP/IP settings.",
            "checks": [
                ("🔌", "Network Adapters"),
                ("📶", "Adapter Speed"),
                ("🌍", "IPv6 Status"),
                ("📏", "MTU"),
                ("📄", "DHCP Lease"),
            ]
        },
        "Network Security": {
            "description":
                "Evaluates network security settings and protocols.",
            "checks": [
                ("🛡", "Windows Firewall Profile"),
                ("📁", "SMB Configuration"),
                ("📢", "LLMNR"),
                ("🛰", "NetBIOS"),
                ("🔒", "Network Isolation"),
            ]
        },
        "Wireless Security": {
            "description":
                "Reviews wireless adapter configuration and Wi-Fi security.",
            "checks": [
                ("📶", "SSID"),
                ("🔐", "Wi-Fi Encryption"),
                ("📡", "Signal Strength"),
            ]
        },
        "Ports & Services": {
            "description":
                "Inspects listening ports and exposed network services.",
            "checks": [
                ("🚪", "Listening Ports"),
                ("⚙", "Running Network Services"),
            ]
        },
        "Active Connections": {
            "description":
                "Displays active network sessions and remote endpoints.",
            "checks": [
                ("🔗", "Established Connections"),
                ("🌍", "Remote Endpoints"),
                ("💻", "Connection Processes"),
                ("📊", "TCP Statistics"),
            ]
        }
    }

    # =====================================================
    # INIT
    # =====================================================

    def __init__(self, parent):
        super().__init__(
            parent,
            fg_color="transparent"
        )
        self.selected_category = "Network Information"
        self.audit_rows = {}
        self.audit_results = {}
        self.selected_checks = []
        self.is_scanning = False
        self.grid_rowconfigure(
            0,
            weight=1
        )
        self.grid_columnconfigure(
            1,
            weight=1
        )
        self.build_left_panel()
        self.build_right_panel()

    # =====================================================
    # LEFT PANEL
    # =====================================================

    def build_left_panel(self):
        self.left_panel = ctk.CTkFrame(
            self,
            width=320,
            corner_radius=15,
            fg_color="#242424"
        )
        self.left_panel.grid(
            row=0,
            column=0,
            padx=(20, 10),
            pady=20,
            sticky="ns"
        )
        self.left_panel.pack_propagate(False)
        title = ctk.CTkLabel(
            self.left_panel,
            text="🌐  Network Audit",
            font=("Segoe UI", 22, "bold")
        )
        title.pack(
            anchor="w",
            padx=20,
            pady=(25, 10)
        )
        subtitle = ctk.CTkLabel(
            self.left_panel,
            text="Categories",
            font=("Segoe UI", 13, "bold"),
            text_color="#D0D0D0"
        )
        subtitle.pack(
            anchor="w",
            padx=20,
            pady=(0, 20)
        )
        self.category_buttons = {}
        for category, data in self.CATEGORIES.items():
            count = len(data["checks"])
            btn = ctk.CTkButton(
                self.left_panel,
                text=f"{category} ({count})",
                anchor="w",
                width=230,
                height=42,
                fg_color="transparent",
                hover_color="#333333",
                corner_radius=8,
                command=lambda c=category: self.show_category(c)
            )
            btn.pack(
                fill="x",
                padx=18,
                pady=4
            )
            self.category_buttons[category] = btn
        self.category_buttons[
            self.selected_category
        ].configure(
            fg_color="#8B0000"
        )

    # =====================================================
    # RIGHT PANEL
    # =====================================================

    def build_right_panel(self):
        self.right_panel = ctk.CTkFrame(
            self,
            corner_radius=15,
            fg_color="#2B2B2B"
        )
        self.right_panel.grid(
            row=0,
            column=1,
            padx=(10, 20),
            pady=20,
            sticky="nsew"
        )
        self.right_panel.grid_columnconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(2, weight=1)

        # =====================================================
        # HEADER
        # =====================================================

        header_frame = ctk.CTkFrame(
            self.right_panel,
            fg_color="transparent"
        )
        header_frame.pack(
            fill="x",
            padx=20,
            pady=(20, 5)
        )

        self.category_title = ctk.CTkLabel(
            header_frame,
            text="",
            font=("Segoe UI", 24, "bold")
        )
        self.category_title.pack(
            side="left"
        )

        self.run_button = ctk.CTkButton(
            header_frame,
            text="🛡 Run Selected",
            width=170,
            height=38,
            fg_color="#8B0000",
            hover_color="#A40000",
            command=self.run_audit
        )
        self.run_button.pack(
            side="right"
        )

        self.category_description = ctk.CTkLabel(
            self.right_panel,
            text="",
            font=("Segoe UI", 13),
            text_color="#9CA3AF"
        )
        self.category_description.pack(
            anchor="w",
            padx=20,
            pady=(0, 20)
        )

        self.content_frame = ctk.CTkFrame(
            self.right_panel,
            fg_color="transparent"
        )
        self.content_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 20)
        )

        # =====================================================
        # SECURITY SCORE CARD
        # =====================================================
        self.score_card = ctk.CTkFrame(
            self.content_frame,
            corner_radius=12,
            fg_color="#242424"
        )
        self.score_card.pack(
            fill="x",
            pady=(0, 15)
        )
        self.score_card.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkLabel(
            self.score_card,
            text="Security Score",
            font=("Segoe UI", 15, "bold")
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=15,
            pady=(12, 5)
        )
        self.score_label = ctk.CTkLabel(
            self.score_card,
            text="0 / 100",
            font=("Segoe UI", 26, "bold"),
            text_color="#EF4444"
        )
        self.score_label.grid(
            row=1,
            column=0,
            sticky="w",
            padx=15
        )
        self.score_status = ctk.CTkLabel(
            self.score_card,
            text="Not Scanned",
            font=("Segoe UI", 12),
            text_color="#9CA3AF"
        )
        self.score_status.grid(
            row=2,
            column=0,
            sticky="w",
            padx=15,
            pady=(0, 10)
        )
        self.score_progress = ctk.CTkProgressBar(
            self.score_card,
            height=12
        )
        self.score_progress.grid(
            row=3,
            column=0,
            columnspan=4,
            sticky="ew",
            padx=15,
            pady=(0, 15)
        )
        self.score_progress.set(0)
        self.passed_label = ctk.CTkLabel(
            self.score_card,
            text="Passed : 0"
        )
        self.warning_label = ctk.CTkLabel(
            self.score_card,
            text="Warning : 0"
        )
        self.critical_label = ctk.CTkLabel(
            self.score_card,
            text="Critical : 0"
        )
        self.remaining_label = ctk.CTkLabel(
            self.score_card,
            text="Remaining : 0"
        )
        self.passed_label.grid(row=4, column=0, padx=15, pady=(0, 12), sticky="w")
        self.warning_label.grid(row=4, column=1, padx=15, pady=(0, 12), sticky="w")
        self.critical_label.grid(row=4, column=2, padx=15, pady=(0, 12), sticky="w")
        self.remaining_label.grid(row=4, column=3, padx=15, pady=(0, 12), sticky="w")

        # =====================================================
        # AUDIT PROGRESS CARD
        # =====================================================
        self.progress_card = ctk.CTkFrame(
            self.content_frame,
            corner_radius=12,
            fg_color="#242424"
        )
        self.progress_card.pack(
            fill="x",
            pady=(0, 15)
        )
        self.progress_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            self.progress_card,
            text="Audit Progress",
            font=("Segoe UI", 15, "bold")
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=15,
            pady=(12, 5)
        )
        self.progress_percent = ctk.CTkLabel(
            self.progress_card,
            text="0%",
            font=("Segoe UI", 15, "bold"),
            text_color="#4EA3FF"
        )
        self.progress_percent.grid(
            row=0,
            column=1,
            sticky="e",
            padx=15
        )
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_card,
            height=12
        )
        self.progress_bar.grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=15,
            pady=(0, 10)
        )
        self.progress_bar.set(0)
        self.current_scanner = ctk.CTkLabel(
            self.progress_card,
            text="Current Scanner : Waiting...",
            font=("Segoe UI", 12)
        )
        self.current_scanner.grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="w",
            padx=15,
            pady=(0, 12)
        )

        self.show_category(
            self.selected_category
        )

    # =====================================================
    # SHOW CATEGORY
    # =====================================================
    def show_category(self, category):
        self.selected_category = category
        for btn in self.category_buttons.values():
            btn.configure(fg_color="transparent")
        self.category_buttons[category].configure(
            fg_color="#8B0000"
        )
        self.category_title.configure(
            text=category
        )
        self.category_description.configure(
            text=self.CATEGORIES[category]["description"]
        )
        for widget in self.content_frame.winfo_children():
            if widget not in (
                self.score_card,
                self.progress_card
            ):
                widget.destroy()
        self.audit_rows = {}
        self.select_all_var = ctk.BooleanVar(value=False)
        select_frame = ctk.CTkFrame(
            self.content_frame,
            fg_color="transparent"
        )
        select_frame.pack(
            fill="x",
            pady=(0, 10)
        )
        select_all = ctk.CTkCheckBox(
            select_frame,
            text="Select Category",
            variable=self.select_all_var,
            command=self.toggle_category
        )
        select_all.pack(
            side="left"
        )
        self.selected_label = ctk.CTkLabel(
            select_frame,
            text="Selected : 0 / 0",
            font=("Segoe UI", 12)
        )
        self.selected_label.pack(
            side="right"
        )
        self.scanner_frame = ctk.CTkScrollableFrame(
            self.content_frame,
            fg_color="transparent"
        )
        self.scanner_frame.pack(
            fill="both",
            expand=True
        )
        for icon, scanner in self.CATEGORIES[category]["checks"]:
            self.create_scanner_row(
                icon,
                scanner
            )
        self.build_bottom_bar()

    # =====================================================
    # CREATE SCANNER ROW
    # =====================================================
    def create_scanner_row(self, icon, scanner):
        row = ctk.CTkFrame(
            self.scanner_frame,
            fg_color="#252525",
            corner_radius=8,
            height=46
        )
        row.pack(
            fill="x",
            pady=4
        )
        row.grid_columnconfigure(
            1,
            weight=1
        )
        check_var = ctk.BooleanVar(value=False)
        checkbox = ctk.CTkCheckBox(
            row,
            text="",
            variable=check_var,
            width=20
        )
        checkbox.grid(
            row=0,
            column=0,
            padx=(16, 6),
            pady=10
        )
        title = ctk.CTkLabel(
            row,
            text=f"{icon}  {scanner}",
            font=("Segoe UI", 13, "bold")
        )
        title.grid(
            row=0,
            column=1,
            sticky="w"
        )
        badge = ctk.CTkLabel(
            row,
            text="⚫ Not Scanned",
            width=130,
            height=28,
            fg_color="#404040",
            corner_radius=12,
            font=("Segoe UI", 11)
        )
        badge.grid(
            row=0,
            column=2,
            padx=10
        )
        details = ctk.CTkButton(
            row,
            text=">",
            width=34,
            height=30,
            fg_color="transparent",
            hover_color="#333333",
            border_width=1,
            border_color="#555555",
            command=lambda s=scanner: self.show_details(s)
        )
        details.grid(
            row=0,
            column=3,
            padx=12
        )
        self.audit_rows[scanner] = {
            "check_var": check_var,
            "badge": badge,
            "button": details
        }

    # =====================================================
    # BOTTOM BAR
    # =====================================================
    def build_bottom_bar(self):
        for row in self.audit_rows.values():
            row["check_var"].trace_add(
                "write",
                self.update_selected_count
            )
        self.update_selected_count()

    # =====================================================
    # SELECT / DESELECT CATEGORY
    # =====================================================
    def toggle_category(self):
        state = self.select_all_var.get()
        for row in self.audit_rows.values():
            row["check_var"].set(state)
        self.update_selected_count()

    # =====================================================
    # UPDATE SELECTED COUNT
    # =====================================================
    def update_selected_count(self, *args):
        selected = sum(
            1
            for row in self.audit_rows.values()
            if row["check_var"].get()
        )
        total = len(self.audit_rows)
        self.selected_label.configure(
            text=f"Selected : {selected} / {total}"
        )

    # =====================================================
    # SHOW DETAILS
    # =====================================================
    def show_details(self, scanner):
        if scanner not in self.audit_results:
            return
        DetailsPopup(
            self,
            scanner,
            self.audit_results[scanner]
        )

    # =====================================================
    # GET SELECTED CHECKS
    # =====================================================
    def get_selected_checks(self):
        return [
            name
            for name, row in self.audit_rows.items()
            if row["check_var"].get()
        ]

    # =====================================================
    # RUN AUDIT
    # =====================================================
    def run_audit(self):
        selected = self.get_selected_checks()
        if not selected:
            return
        self.is_scanning = True
        self.run_button.configure(
            text="Running...",
            state="disabled"
        )
        self.progress_bar.set(0)
        self.progress_percent.configure(
            text="0%"
        )
        self.current_scanner.configure(
            text="Preparing audit..."
        )
        self.audit_results = {}
        total = len(selected)
        passed = 0
        warning = 0
        critical = 0
        for current, scanner in enumerate(selected, start=1):
            # ==========================================
            # TEMPORARY RESULT
            # Replace this with real scanner later
            # ==========================================
            result = {
                "status": "Passed",
                "details": "Scanner not implemented yet."
            }
            self.audit_results[scanner] = result
            self.audit_progress(
                current,
                total,
                scanner,
                result
            )
            if result["status"] == "Passed":
                passed += 1
            elif result["status"] == "Warning":
                warning += 1
            else:
                critical += 1
        score = int((passed / total) * 100)
        self.finish_scan(
            score,
            passed,
            warning,
            critical,
            total
        )

    # =====================================================
    # LIVE PROGRESS
    # =====================================================
    def audit_progress(
        self,
        current,
        total,
        scanner,
        result
    ):
        percent = int((current / total) * 100)
        self.progress_bar.set(
            percent / 100
        )
        self.progress_percent.configure(
            text=f"{percent}%"
        )
        self.current_scanner.configure(
            text=f"Scanning : {scanner}"
        )
        badge = self.audit_rows[scanner]["badge"]
        status = result["status"]
        if status == "Passed":
            badge.configure(
                text="🟢 Passed",
                fg_color="#16A34A"
            )
        elif status == "Warning":
            badge.configure(
                text="🟡 Warning",
                fg_color="#D97706"
            )
        else:
            badge.configure(
                text="🔴 Critical",
                fg_color="#DC2626"
            )
        self.update_idletasks()

    # =====================================================
    # FINISH AUDIT
    # =====================================================
    def finish_scan(
        self,
        score,
        passed,
        warning,
        critical,
        total
    ):
        self.score_label.configure(
            text=f"{score} / 100"
        )
        self.score_progress.set(
            score / 100
        )
        self.passed_label.configure(
            text=f"Passed : {passed}"
        )
        self.warning_label.configure(
            text=f"Warning : {warning}"
        )
        self.critical_label.configure(
            text=f"Critical : {critical}"
        )
        self.remaining_label.configure(
            text="Remaining : 0"
        )
        if score >= 90:
            level = "Excellent"
            color = "#16A34A"
        elif score >= 80:
            level = "Good"
            color = "#65A30D"
        elif score >= 60:
            level = "Fair"
            color = "#D97706"
        elif score >= 40:
            level = "Poor"
            color = "#DC2626"
        else:
            level = "Critical"
            color = "#991B1B"
        self.score_status.configure(
            text=level,
            text_color=color
        )
        self.progress_bar.set(1)
        self.progress_percent.configure(
            text="100%"
        )
        self.current_scanner.configure(
            text="Audit Completed"
        )
        self.run_button.configure(
            text="🛡 Run Selected",
            state="normal"
        )
        self.is_scanning = False
        AuditCache.set_results(
            self.audit_results
        )
