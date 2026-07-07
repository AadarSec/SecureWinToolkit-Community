import subprocess
import customtkinter as ctk
from tkinter import messagebox
from src.audit.audit_manager import run_windows_audit

class WindowsAudit(ctk.CTkFrame):

    CHECKS = [
        ("🛡", "Windows Defender"),
        ("🧱", "Firewall"),
        ("🔒", "BitLocker"),
        ("🖥", "Secure Boot"),
        ("💻", "TPM"),
        ("🛡", "SmartScreen"),
        ("👤", "User Account Control"),
        ("🔄", "Windows Update"),
    ]

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        self.audit_rows = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.build_header()
        self.build_overview()
        self.build_results()
        self.scan_progress = 0
        self.is_scanning = False

    # =====================================================
    # HEADER
    # =====================================================

    def build_header(self):

        header = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        header.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=20,
            pady=(15, 10)
        )

        header.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(
            header,
            fg_color="transparent"
        )

        left.grid(
            row=0,
            column=0,
            sticky="w"
        )

        ctk.CTkLabel(
            left,
            text="Windows Audit",
            font=("Segoe UI", 30, "bold")
        ).pack(anchor="w")

        ctk.CTkLabel(
            left,
            text="Perform a complete Windows Security Assessment",
            font=("Segoe UI", 13),
            text_color="#9CA3AF"
        ).pack(anchor="w", pady=(2, 5))

        self.last_scan = ctk.CTkLabel(
            left,
            text="🕒 Last Audit : Never",
            font=("Segoe UI", 12),
            text_color="#B0B0B0"
        )

        self.last_scan.pack(anchor="w")

        self.run_button = ctk.CTkButton(
            header,
            text="🛡 Run Audit",
            width=210,
            height=46,
            fg_color="#8B0000",
            hover_color="#A40000",
            command=self.run_audit
        )

        self.run_button.grid(
            row=0,
            column=1,
            rowspan=2,
            sticky="ne"
        )

    # =====================================================
    # OVERVIEW
    # =====================================================

    def build_overview(self):

        overview = ctk.CTkFrame(
            self,
            fg_color="#2B2B2B",
            corner_radius=12,
            border_width=1,
            border_color="#404040"
        )

        overview.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=20,
            pady=(5, 15)
        )

        overview.grid_columnconfigure(0, weight=2)
        overview.grid_columnconfigure(1, weight=1)

        # ---------------- LEFT PANEL ----------------

        left = ctk.CTkFrame(
            overview,
            fg_color="transparent"
        )

        left.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(20, 10),
            pady=20
        )

        ctk.CTkLabel(
            left,
            text="Security Score",
            font=("Segoe UI", 18, "bold")
        ).pack(anchor="w")

        self.score_label = ctk.CTkLabel(
            left,
            text="0 / 100",
            font=("Segoe UI", 38, "bold"),
            text_color="#EF4444"
        )

        self.score_label.pack(anchor="w")

        self.score_status = ctk.CTkLabel(
            left,
            text="Very Weak",
            font=("Segoe UI", 13),
            text_color="#EF4444"
        )

        self.score_status.pack(anchor="w", pady=(0, 10))

        self.progress = ctk.CTkProgressBar(
            left,
            height=12
        )

        self.progress.pack(fill="x")
        self.progress.set(0)

        # ---------------- RIGHT PANEL ----------------

        right = ctk.CTkFrame(
            overview,
            fg_color="#242424",
            corner_radius=10
        )

        right.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(10, 20),
            pady=20
        )

        ctk.CTkLabel(
            right,
            text="Overall Status",
            font=("Segoe UI", 17, "bold")
        ).pack(anchor="w", padx=18, pady=(15, 12))

        self.total_checks = ctk.CTkLabel(
            right,
            text="Total Checks : 8",
            anchor="w"
        )

        self.total_checks.pack(fill="x", padx=18, pady=3)

        self.pass_label = ctk.CTkLabel(
            right,
            text="🟢 Passed : 0",
            anchor="w"
        )

        self.pass_label.pack(fill="x", padx=18, pady=3)

        self.warning_label = ctk.CTkLabel(
            right,
            text="🟡 Warnings : 0",
            anchor="w"
        )

        self.warning_label.pack(fill="x", padx=18, pady=3)

        self.critical_label = ctk.CTkLabel(
            right,
            text="🔴 Critical : 0",
            anchor="w"
        )

        self.critical_label.pack(fill="x", padx=18, pady=(3, 15))

    # =====================================================
    # RESULTS
    # =====================================================

    def build_results(self):

        self.results_container = ctk.CTkFrame(
            self,
            fg_color="#2B2B2B",
            corner_radius=12,
            border_width=1,
            border_color="#404040"
        )

        self.results_container.grid(
            row=2,
            column=0,
            padx=20,
            pady=(0, 20),
            sticky="nsew"
        )

        self.results_container.grid_rowconfigure(2, weight=1)
        self.results_container.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            self.results_container,
            text="Audit Results",
            font=("Segoe UI", 18, "bold")
        )

        title.grid(
            row=0,
            column=0,
            sticky="w",
            padx=20,
            pady=(18, 10)
        )

        header = ctk.CTkFrame(
            self.results_container,
            fg_color="#252525",
            corner_radius=8,
            height=36
        )

        header.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=15
        )

        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Check Item",
            font=("Segoe UI", 12, "bold"),
            text_color="#BFBFBF"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=18,
            pady=8
        )

        ctk.CTkLabel(
            header,
            text="Status",
            font=("Segoe UI", 12, "bold"),
            text_color="#BFBFBF"
        ).grid(
            row=0,
            column=1,
            padx=20
        )

        ctk.CTkLabel(
            header,
            text="Details",
            font=("Segoe UI", 12, "bold"),
            text_color="#BFBFBF"
        ).grid(
            row=0,
            column=2,
            padx=20
        )

        self.results_frame = ctk.CTkScrollableFrame(
            self.results_container,
            fg_color="transparent"
        )

        self.results_frame.grid(
            row=2,
            column=0,
            sticky="nsew",
            padx=12,
            pady=(8, 12)
        )

        for icon, name in self.CHECKS:
            self.create_result_row(icon, name)

    # =====================================================
    # RESULT ROW
    # =====================================================

    def create_result_row(self, icon, name):

        row = ctk.CTkFrame(
            self.results_frame,
            fg_color="#252525",
            corner_radius=8,
            height=48
        )

        row.pack(
            fill="x",
            pady=4
        )

        row.grid_columnconfigure(0, weight=1)

        name_label = ctk.CTkLabel(
            row,
            text=f"{icon}  {name}",
            font=("Segoe UI", 13, "bold")
        )

        name_label.grid(
            row=0,
            column=0,
            padx=16,
            pady=10,
            sticky="w"
        )

        status_badge = ctk.CTkLabel(
            row,
            text="⚫ Not Scanned",
            fg_color="#404040",
            corner_radius=12,
            width=130,
            height=28,
            font=("Segoe UI", 11)
        )

        status_badge.grid(
            row=0,
            column=1,
            padx=10
        )

        details_button = ctk.CTkButton(
            row,
            text=">",
            width=34,
            height=30,
            fg_color="transparent",
            hover_color="#333333",
            border_width=1,
            border_color="#555555",
            command=lambda n=name: self.show_details(n)
        )

        details_button.grid(
            row=0,
            column=2,
            padx=12
        )

        self.audit_rows[name] = {
            "row": row,
            "badge": status_badge,
            "button": details_button
        }

    # =====================================================
    # DETAILS
    # =====================================================

    def show_details(self, check_name):

        if not hasattr(self, "audit_results") or not self.audit_results:

            messagebox.showwarning(
                "SecureWin Toolkit",
                "Please run Windows Audit first."
            )

            return

        result = self.audit_results.get(check_name)

        if result is None:

            messagebox.showwarning(
                "SecureWin Toolkit",
                "No audit information found."
            )

            return

        messagebox.showinfo(

            check_name,

            f"""
Status : {result.get('status', 'N/A')}

Risk : {result.get('risk', 'N/A')}

Details :

{result.get('details', 'N/A')}

Recommendation :

{result.get('recommendation', 'N/A')}
"""
        )

    # =====================================================
    # RUN AUDIT
    # =====================================================

    def run_audit(self):

        self.audit_results = {}

        if self.is_scanning:
            return

        self.is_scanning = True

        self.run_button.configure(
            text="🛡 Running Audit...",
            state="disabled"
        )

        self.progress.set(0)

        self.scan_progress = 0

        self.animate_scan()

    # =====================================================
    # FINISH SCAN (uses real audit results)
    # =====================================================

    def finish_scan(self):

        self.audit_results = run_windows_audit()

        results = self.audit_results

        passed = 0
        warnings = 0
        critical = 0

        for name, result in results.items():

            status = result["status"]

            if status == "Passed":
                color = "#16A34A"
                icon = "🟢"
                passed += 1

            elif status == "Warning":
                color = "#D97706"
                icon = "🟡"
                warnings += 1

            else:
                color = "#DC2626"
                icon = "🔴"
                critical += 1

            if name in self.audit_rows:
                self.audit_rows[name]["badge"].configure(
                    text=f"{icon} {status}",
                    fg_color=color
                )

        score = int((passed / len(self.CHECKS)) * 100)

        self.score_label.configure(
            text=f"{score} / 100"
        )

        self.progress.set(score / 100)

        self.pass_label.configure(
            text=f"🟢 Passed : {passed}"
        )

        self.warning_label.configure(
            text=f"🟡 Warnings : {warnings}"
        )

        self.critical_label.configure(
            text=f"🔴 Critical : {critical}"
        )

        self.last_scan.configure(
            text="🕒 Last Audit : Just Now"
        )

        if score >= 80:

            self.score_status.configure(
                text="Excellent",
                text_color="#16A34A"
            )

        elif score >= 60:

            self.score_status.configure(
                text="Good",
                text_color="#D97706"
            )

        else:

            self.score_status.configure(
                text="Needs Attention",
                text_color="#DC2626"
            )

    # =====================================================
    # ANIMATE SCAN
    # =====================================================

    def animate_scan(self):

        if self.scan_progress >= 100:

            self.is_scanning = False

            self.run_button.configure(
                text="🛡 Run Audit",
                state="normal"
            )

            self.finish_scan()

            return

        self.scan_progress += 5

        self.progress.set(
            self.scan_progress / 100
        )

        self.after(
            70,
            self.animate_scan
        )