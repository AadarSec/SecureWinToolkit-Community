import datetime
import tkinter as tk

import customtkinter as ctk

from src.core.audit_cache import AuditCache
from src.core.score_engine import score_engine

# ==========================================================
# THEME
# ==========================================================

BG = "#181818"
PANEL = "#242424"
CARD = "#2D2D2D"
BORDER = "#3B3B3B"
ACCENT = "#B3131B"
GREEN = "#22C55E"
YELLOW = "#F59E0B"
RED = "#EF4444"
BLUE = "#3B82F6"
TEXT = "#F3F4F6"
MUTED = "#A1A1AA"

REFRESH_INTERVAL = 2000


# ==========================================================
# DASHBOARD
# ==========================================================

class Dashboard(ctk.CTkFrame):

    def __init__(self, parent, controller=None):
        super().__init__(parent, fg_color=BG)
        self.controller = controller
        self.system = self._get_system_info_safe()
        self.refresh_job = None
        self.build_layout()
        self.after(500, self.update_dashboard)

    # =====================================================
    # SAFE SYSTEM INFO (graceful fallback)
    # =====================================================

    def _get_system_info_safe(self):
        """Attempt to load system info, fall back to defaults."""
        try:
            from src.utils.system_info import get_system_info
            return get_system_info()
        except Exception as e:
            print(f"[Dashboard] Could not load system info: {e}")
            return {
                "Computer Name": "N/A",
                "Current User": "N/A",
                "Windows Edition": "N/A",
                "Windows Version": "N/A",
                "Windows Build": "N/A",
                "Processor": "N/A",
                "IP Address": "N/A",
                "Uptime": "N/A",
            }

    # =====================================================
    # LAYOUT
    # =====================================================

    def build_layout(self):
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.build_header()

        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))

        for i in range(3):
            self.body.grid_columnconfigure(i, weight=1, uniform="dashboard")

        self.body.grid_rowconfigure(0, weight=1)
        self.body.grid_rowconfigure(1, weight=0)

        # --- Top panels ---
        self.left_panel = self.create_panel()
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self.center_panel = self.create_panel()
        self.center_panel.grid(row=0, column=1, sticky="nsew", padx=4)

        self.right_panel = self.create_panel()
        self.right_panel.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        # --- Bottom panels ---
        self.bottom_left = self.create_panel(height=185)
        self.bottom_left.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        self.bottom_right = self.create_panel(height=185)
        self.bottom_right.grid(row=1, column=2, sticky="nsew", padx=(8, 0), pady=(12, 0))

        # --- Populate panels ---
        self.build_header_contents()
        self.build_security_panel()
        self.build_system_panel()
        self.build_performance_panel()
        self.build_status_panel()
        self.build_quick_actions()

    # =====================================================
    # COMMON PANEL  ← THIS WAS MISSING
    # =====================================================

    def create_panel(self, height=None):
        kwargs = {
            "fg_color": PANEL,
            "corner_radius": 14,
            "border_width": 1,
            "border_color": BORDER,
        }
        if height is not None:
            kwargs["height"] = height

        frame = ctk.CTkFrame(self.body, **kwargs)

        if height is not None:
            frame.grid_propagate(False)

        return frame

    # =====================================================
    # HEADER
    # =====================================================

    def build_header(self):
        self.header = ctk.CTkFrame(self, fg_color=BG, height=85)
        self.header.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 10))
        self.header.grid_columnconfigure(0, weight=1)
        self.header.grid_columnconfigure(1, weight=0)

    def build_header_contents(self):
        # LEFT SIDE
        left = ctk.CTkFrame(self.header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            left, text="Security Dashboard",
            font=("Segoe UI", 30, "bold"), text_color=TEXT
        ).pack(anchor="w")

        ctk.CTkLabel(
            left, text="Real-time Security Posture and System Health",
            font=("Segoe UI", 12), text_color=MUTED
        ).pack(anchor="w", pady=(4, 0))

        # RIGHT SIDE
        right = ctk.CTkFrame(self.header, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e")

        row1 = ctk.CTkFrame(right, fg_color="transparent")
        row1.pack(anchor="e")

        self.last_scan = ctk.CTkLabel(
            row1, text="Last Scan : --:--:--",
            font=("Segoe UI", 11), text_color=MUTED
        )
        self.last_scan.pack(side="left", padx=(0, 15))

        ctk.CTkLabel(
            row1, text="Refresh",
            font=("Segoe UI", 11), text_color=MUTED
        ).pack(side="left", padx=(0, 8))

        self.refresh_combo = ctk.CTkOptionMenu(
            row1, values=["2s", "5s", "10s"],
            width=80, command=self.change_refresh_interval
        )
        self.refresh_combo.set("2s")
        self.refresh_combo.pack(side="left")

        row2 = ctk.CTkFrame(right, fg_color="transparent")
        row2.pack(anchor="e", pady=(10, 0))

        self.header_status = ctk.CTkLabel(
            row2, text="● HEALTHY",
            font=("Segoe UI", 16, "bold"), text_color=GREEN
        )
        self.header_status.pack(anchor="e")

        self.header_summary = ctk.CTkLabel(
            row2, text="0 Critical | 0 Warning | 0 Information",
            font=("Segoe UI", 11), text_color=MUTED
        )
        self.header_summary.pack(anchor="e", pady=(3, 0))

    # =====================================================
    # SECTION TITLE
    # =====================================================

    def section_title(self, parent, text):
        ctk.CTkLabel(
            parent, text=text,
            font=("Segoe UI", 18, "bold"), text_color=TEXT
        ).pack(anchor="w", padx=18, pady=(18, 15))

    # =====================================================
    # REFRESH
    # =====================================================

    def change_refresh_interval(self, value):
        global REFRESH_INTERVAL
        REFRESH_INTERVAL = int(value.replace("s", "")) * 1000

        if self.refresh_job:
            self.after_cancel(self.refresh_job)

        self.update_dashboard()

    # =====================================================
    # SECURITY PANEL
    # =====================================================

    def build_security_panel(self):
        self.section_title(self.left_panel, "SECURITY OVERVIEW")

        container = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # --- Overall Status Card ---
        self.status_card = ctk.CTkFrame(
            container, fg_color=CARD, border_width=1,
            border_color=BORDER, corner_radius=12, height=105
        )
        self.status_card.pack(fill="x", pady=(0, 12))
        self.status_card.pack_propagate(False)

        row = ctk.CTkFrame(self.status_card, fg_color="transparent")
        row.pack(fill="both", expand=True, padx=18, pady=15)

        self.status_icon = ctk.CTkLabel(row, text="🛡", font=("Segoe UI", 34))
        self.status_icon.pack(side="left")

        text_frame = ctk.CTkFrame(row, fg_color="transparent")
        text_frame.pack(side="left", padx=15, fill="both", expand=True)

        ctk.CTkLabel(
            text_frame, text="OVERALL STATUS",
            font=("Segoe UI", 11, "bold"), text_color=MUTED
        ).pack(anchor="w")

        self.overall_status = ctk.CTkLabel(
            text_frame, text="HEALTHY",
            font=("Segoe UI", 24, "bold"), text_color=GREEN
        )
        self.overall_status.pack(anchor="w")

        # --- Security Posture Card ---
        self.posture_card = ctk.CTkFrame(
            container, fg_color=CARD, border_width=1,
            border_color=BORDER, corner_radius=12, height=245
        )
        self.posture_card.pack(fill="x", pady=(0, 12))
        self.posture_card.pack_propagate(False)

        ctk.CTkLabel(
            self.posture_card, text="SECURITY POSTURE",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))

        body = ctk.CTkFrame(self.posture_card, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Gauge
        self.score_canvas = tk.Canvas(
            body, width=170, height=170,
            bg=CARD, highlightthickness=0
        )
        self.score_canvas.grid(row=0, column=0, padx=(0, 18))

        self.score_canvas.create_oval(22, 22, 148, 148, outline="#404040", width=10)
        self.score_arc = self.score_canvas.create_arc(
            22, 22, 148, 148, start=90, extent=-360,
            style="arc", outline=GREEN, width=10
        )
        self.score_text = self.score_canvas.create_text(
            85, 85, text="100%", fill="white", font=("Segoe UI", 20, "bold")
        )

        # Right info
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nw")

        self.posture_name = ctk.CTkLabel(
            right, text="Excellent",
            font=("Segoe UI", 18, "bold"), text_color=GREEN
        )
        self.posture_name.pack(anchor="w", pady=(10, 10))

        self.windows_score = ctk.CTkLabel(
            right, text="Windows Audit : --%", font=("Segoe UI", 12)
        )
        self.windows_score.pack(anchor="w")

        self.network_score = ctk.CTkLabel(
            right, text="Network Audit : --%", font=("Segoe UI", 12)
        )
        self.network_score.pack(anchor="w", pady=(8, 0))

        self.remaining_issues = ctk.CTkLabel(
            right, text="Remaining Issues : 0", font=("Segoe UI", 12)
        )
        self.remaining_issues.pack(anchor="w", pady=(20, 0))

        # --- Audit Summary Card ---
        self.summary_card = ctk.CTkFrame(
            container, fg_color=CARD, border_width=1,
            border_color=BORDER, corner_radius=12, height=170
        )
        self.summary_card.pack(fill="x")
        self.summary_card.pack_propagate(False)

        ctk.CTkLabel(
            self.summary_card, text="AUDIT SUMMARY",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))

        self.windows_summary = ctk.CTkLabel(
            self.summary_card, text="Windows Audit\nNot Scanned",
            justify="left", anchor="w", font=("Segoe UI", 12)
        )
        self.windows_summary.pack(anchor="w", padx=15)

        divider = ctk.CTkFrame(self.summary_card, height=1, fg_color="#3D3D3D")
        divider.pack(fill="x", padx=15, pady=10)

        self.network_summary = ctk.CTkLabel(
            self.summary_card, text="Network Audit\nNot Scanned",
            justify="left", anchor="w", font=("Segoe UI", 12)
        )
        self.network_summary.pack(anchor="w", padx=15)

    # =====================================================
    # SYSTEM INFORMATION
    # =====================================================

    def build_system_panel(self):
        self.section_title(self.center_panel, "SYSTEM INFORMATION")

        grid = ctk.CTkFrame(self.center_panel, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        grid.grid_columnconfigure(0, weight=1)
        grid.grid_columnconfigure(1, weight=1)

        info = self.system

        cards = [
            ("🖥", "HOST NAME", info.get("Computer Name", "N/A")),
            ("👤", "CURRENT USER", info.get("Current User", "N/A")),
            ("🪟", "WINDOWS", info.get("Windows Edition", "N/A")),
            ("📦", "VERSION", info.get("Windows Version", "N/A")),
            ("🔨", "BUILD", info.get("Windows Build", "N/A")),
            ("💻", "PROCESSOR", info.get("Processor", "N/A")),
            ("🌐", "IP ADDRESS", info.get("IP Address", "N/A")),
            ("⏱", "UPTIME", info.get("Uptime", "N/A")),
        ]

        row = 0
        col = 0
        for icon, title, value in cards:
            card = self.create_info_tile(grid, icon, title, value)
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            col += 1
            if col == 2:
                col = 0
                row += 1

    # =====================================================
    # INFO TILE
    # =====================================================

    def create_info_tile(self, parent, icon, title, value):
        card = ctk.CTkFrame(
            parent, fg_color=CARD, border_width=1,
            border_color=BORDER, corner_radius=12, width=250, height=118
        )
        card.grid_propagate(False)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(12, 6))

        icon_frame = ctk.CTkFrame(
            header, width=36, height=36,
            fg_color=ACCENT, corner_radius=8
        )
        icon_frame.pack(side="left")
        icon_frame.pack_propagate(False)

        ctk.CTkLabel(icon_frame, text=icon, font=("Segoe UI", 16)).pack(expand=True)

        ctk.CTkLabel(
            header, text=title,
            font=("Segoe UI", 11, "bold"), text_color=MUTED
        ).pack(side="left", padx=10)

        ctk.CTkLabel(
            card, text=value,
            justify="left", anchor="w", wraplength=205,
            font=("Segoe UI", 13)
        ).pack(anchor="w", padx=15, pady=(4, 0))

        return card

    # =====================================================
    # PERFORMANCE PANEL
    # =====================================================

    def build_performance_panel(self):
        self.section_title(self.right_panel, "PERFORMANCE MONITOR")

        container = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.cpu_card = self.create_metric_card(container, "⚙", "CPU USAGE")
        self.ram_card = self.create_metric_card(container, "🧠", "MEMORY USAGE")
        self.disk_card = self.create_metric_card(container, "💽", "DISK ACTIVITY")
        self.storage_card = self.create_metric_card(container, "💾", "STORAGE")

    # =====================================================
    # METRIC CARD
    # =====================================================

    def create_metric_card(self, parent, icon, title):
        card = ctk.CTkFrame(
            parent, fg_color=CARD, border_width=1,
            border_color=BORDER, corner_radius=12, height=115
        )
        card.pack(fill="x", pady=(0, 12))
        card.pack_propagate(False)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(12, 6))

        icon_box = ctk.CTkFrame(
            header, width=38, height=38,
            fg_color=ACCENT, corner_radius=8
        )
        icon_box.pack(side="left")
        icon_box.pack_propagate(False)

        ctk.CTkLabel(icon_box, text=icon, font=("Segoe UI", 17)).pack(expand=True)

        text = ctk.CTkFrame(header, fg_color="transparent")
        text.pack(side="left", padx=12, fill="x", expand=True)

        ctk.CTkLabel(
            text, text=title,
            font=("Segoe UI", 11, "bold"), text_color=MUTED
        ).pack(anchor="w")

        value = ctk.CTkLabel(
            text, text="0%",
            font=("Segoe UI", 24, "bold"), text_color=TEXT
        )
        value.pack(anchor="w")

        progress = ctk.CTkProgressBar(card, height=9, progress_color=ACCENT)
        progress.pack(fill="x", padx=15, pady=(6, 12))
        progress.set(0)

        subtitle = ctk.CTkLabel(
            card, text="",
            font=("Segoe UI", 10), text_color=MUTED
        )
        subtitle.pack(anchor="w", padx=15, pady=(0, 8))

        card.value = value
        card.progress = progress
        card.subtitle = subtitle

        return card

    # =====================================================
    # SECURITY STATUS OVERVIEW
    # =====================================================

    def build_status_panel(self):
        self.section_title(self.bottom_left, "SECURITY STATUS OVERVIEW")

        container = ctk.CTkFrame(self.bottom_left, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        for i in range(4):
            container.grid_columnconfigure(i, weight=1)

        self.passed_tile = self.create_status_tile(container, "PASSED", GREEN)
        self.warning_tile = self.create_status_tile(container, "WARNING", YELLOW)
        self.critical_tile = self.create_status_tile(container, "CRITICAL", RED)
        self.info_tile = self.create_status_tile(container, "INFORMATION", BLUE)

        self.passed_tile.grid(row=0, column=0, padx=6, sticky="nsew")
        self.warning_tile.grid(row=0, column=1, padx=6, sticky="nsew")
        self.critical_tile.grid(row=0, column=2, padx=6, sticky="nsew")
        self.info_tile.grid(row=0, column=3, padx=6, sticky="nsew")

    # =====================================================
    # STATUS TILE
    # =====================================================

    def create_status_tile(self, parent, title, color):
        card = ctk.CTkFrame(
            parent, fg_color=CARD, border_width=1,
            border_color=BORDER, corner_radius=12, height=95
        )
        card.grid_propagate(False)

        value = ctk.CTkLabel(
            card, text="0",
            font=("Segoe UI", 28, "bold"), text_color=color
        )
        value.pack(pady=(14, 0))

        ctk.CTkLabel(
            card, text=title,
            font=("Segoe UI", 11, "bold"), text_color=MUTED
        ).pack()

        card.value = value
        return card

    # =====================================================
    # QUICK ACTIONS
    # =====================================================

    def build_quick_actions(self):
        self.section_title(self.bottom_right, "QUICK ACTIONS")

        body = ctk.CTkFrame(self.bottom_right, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=18, pady=(0, 15))

        ctk.CTkButton(
            body, text="↻ Refresh Dashboard", height=42,
            fg_color=ACCENT, hover_color="#8E1018",
            command=self.update_dashboard
        ).pack(fill="x", pady=(0, 10))

        ctk.CTkButton(
            body, text="🛡 Windows Audit", height=42,
            fg_color="#343434", hover_color="#444444",
            command=self.open_windows_audit
        ).pack(fill="x", pady=(0, 10))

        ctk.CTkButton(
            body, text="🌐 Network Audit", height=42,
            fg_color="#343434", hover_color="#444444",
            command=self.open_network_audit
        ).pack(fill="x")

    # =====================================================
    # PAGE NAVIGATION
    # =====================================================

    def open_windows_audit(self):
        if self.controller:
            self.controller.show_windows_audit()

    def open_network_audit(self):
        if self.controller:
            self.controller.show_network_audit()

    # =====================================================
    # DASHBOARD DATA
    # =====================================================

    def collect_dashboard_data(self):
        data = {
            "passed": 0, "warning": 0,
            "critical": 0, "information": 0,
            "windows_results": {}, "network_results": {},
            "merged_results": {},
            "windows_score": 100, "network_score": 100,
            "overall_score": 100, "posture": None,
        }

        if AuditCache.has_results():
            cache = AuditCache.get_all_results()
            data["windows_results"] = cache.get("windows", {})
            data["network_results"] = cache.get("network", {})
            merged = {}
            merged.update(data["windows_results"])
            merged.update(data["network_results"])
            data["merged_results"] = merged

        score_engine.refresh(data["merged_results"])
        summary = score_engine.calculate_summary()

        data["windows_score"] = summary.get("windows_score", 100)
        data["network_score"] = summary.get("network_score", 100)
        data["overall_score"] = summary.get("overall_score", 100)
        data["posture"] = summary.get("security_posture", "Excellent")

        stats = score_engine.get_statistics()
        data["passed"] = stats["passed"]
        data["warning"] = stats["warning"]
        data["critical"] = stats["critical"]
        data["information"] = stats["information"]

        return data

    # =====================================================
    # PERFORMANCE UPDATE
    # =====================================================

    def update_performance_cards(self):
        from src.services.monitor_service import (
            get_cpu_usage, get_ram_usage, get_disk_activity
        )
        from src.utils.system_info import get_disk_details

        cpu = get_cpu_usage()
        ram = get_ram_usage()
        disk = get_disk_activity()
        storage, used, total = get_disk_details()

        cards = [
            (self.cpu_card, cpu, ""),
            (self.ram_card, ram, ""),
            (self.disk_card, disk, ""),
            (self.storage_card, storage, f"{used} GB / {total} GB"),
        ]

        for card, value, subtitle in cards:
            card.value.configure(text=f"{value:.0f}%")
            card.progress.set(value / 100)
            card.subtitle.configure(text=subtitle)

    # =====================================================
    # UI UPDATE
    # =====================================================

    def update_dashboard_ui(self, data):
        score = max(0, min(round(data["overall_score"]), 100))

        self.score_canvas.itemconfigure(self.score_text, text=f"{score}%")
        self.score_canvas.itemconfigure(self.score_arc, extent=-(360 * score / 100))

        posture = str(data["posture"])

        color = GREEN
        if posture.lower() in ("poor", "critical"):
            color = RED
        elif posture.lower() in ("fair", "warning", "average"):
            color = YELLOW

        self.score_canvas.itemconfigure(self.score_arc, outline=color)
        self.posture_name.configure(text=posture, text_color=color)

        if data["critical"] > 0:
            overall, overall_color = "CRITICAL", RED
        elif data["warning"] > 0:
            overall, overall_color = "WARNING", YELLOW
        else:
            overall, overall_color = "HEALTHY", GREEN

        self.overall_status.configure(text=overall, text_color=overall_color)
        self.header_status.configure(text=f"● {overall}", text_color=overall_color)

        self.header_summary.configure(
            text=f'{data["critical"]} Critical | '
                 f'{data["warning"]} Warning | '
                 f'{data["information"]} Information'
        )

        self.passed_tile.value.configure(text=str(data["passed"]))
        self.warning_tile.value.configure(text=str(data["warning"]))
        self.critical_tile.value.configure(text=str(data["critical"]))
        self.info_tile.value.configure(text=str(data["information"]))

        self.windows_score.configure(
            text=f"Windows Audit : {round(data['windows_score'])}%"
        )
        self.network_score.configure(
            text=f"Network Audit : {round(data['network_score'])}%"
        )

        issues = data["warning"] + data["critical"]
        self.remaining_issues.configure(text=f"Remaining Issues : {issues}")

        windows_total = len(data["windows_results"])
        network_total = len(data["network_results"])

        self.windows_summary.configure(
            text=f"Windows Audit\n\nScanners : {windows_total}\n"
                 f"Score : {round(data['windows_score'])}%"
        )
        self.network_summary.configure(
            text=f"Network Audit\n\nScanners : {network_total}\n"
                 f"Score : {round(data['network_score'])}%"
        )

        now = datetime.datetime.now()
        self.last_scan.configure(text=f"Last Scan : {now:%H:%M:%S}")

    # =====================================================
    # MAIN UPDATE LOOP
    # =====================================================

    def update_dashboard(self):
        try:
            self.update_performance_cards()
            data = self.collect_dashboard_data()
            self.update_dashboard_ui(data)
        except Exception as e:
            print(f"[Dashboard] {e}")
        finally:
            if self.refresh_job:
                self.after_cancel(self.refresh_job)
            self.refresh_job = self.after(REFRESH_INTERVAL, self.update_dashboard)

    # =====================================================
    # CLEANUP
    # =====================================================

    def destroy(self):
        if self.refresh_job:
            try:
                self.after_cancel(self.refresh_job)
            except Exception:
                pass
        super().destroy()