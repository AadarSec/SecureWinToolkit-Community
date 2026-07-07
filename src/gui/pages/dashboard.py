import datetime

import customtkinter as ctk

from src.gui.components.info_card import InfoCard
from src.utils.system_info import get_system_info, get_disk_details
from src.utils.security_info import get_security_info
from src.services.monitor_service import (
    get_cpu_usage,
    get_ram_usage,
    get_disk_usage,
    get_disk_activity,
)

COLUMNS = 4
APP_VERSION = "SecureWin Toolkit v0.1.0-dev"
REFRESH_INTERVALS_MS = {"2s": 2000, "5s": 5000, "10s": 10000}
DEFAULT_REFRESH_CHOICE = "2s"
STATUS_COLORS = {"healthy": "#22C55E", "warning": "#F59E0B", "critical": "#EF4444"}


class Dashboard(ctk.CTkFrame):
    """
    Single-page dashboard (no scrolling). Everything fits on one screen
    using a 4-column grid. Cards in a warning/critical state are
    clickable and show a details popup explaining the issue.
    """

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        self.cards = {}
        self.refresh_interval_ms = REFRESH_INTERVALS_MS[DEFAULT_REFRESH_CHOICE]
        self._refresh_job = None
        self._last_scan_time = None

        heading = ctk.CTkLabel(
            self,
            text="Security Dashboard",
            font=("Segoe UI", 26, "bold")
        )
        heading.grid(row=0, column=0, columnspan=COLUMNS - 1, sticky="w",
                     padx=20, pady=(16, 8))

        self.build_header()

        # `uniform` ties every column (and every card row) to the same
        # size as one another, so no single tile can grow/shrink on its
        # own just because its text happens to be longer or shorter than
        # its neighbors'. `minsize` sets the baseline card size; `weight`
        # then lets that shared size scale up/down together to fill
        # whatever space the window actually has, so nothing overflows
        # and nothing needs to scroll.
        for i in range(COLUMNS):
            self.grid_columnconfigure(i, weight=1, uniform="dash_col", minsize=220)

        # 16 cards over 4 columns = 4 rows, plus the heading row (row 0)
        # and a fixed-height footer row (row 5) for scan/refresh timestamps.
        self.grid_rowconfigure(0, weight=0)
        for r in range(1, 5):
            self.grid_rowconfigure(r, weight=1, uniform="dash_row", minsize=130)
        self.grid_rowconfigure(5, weight=0)

        self.build_cards()
        self.build_footer()
        self.update_live()

    def build_header(self):
        self.header_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.header_frame.grid(
            row=0,
            column=COLUMNS - 1,
            sticky="e",
            padx=20,
            pady=16
        )

        self.status_badge = ctk.CTkLabel(
            self.header_frame,
            text="🟢 System Healthy",
            font=("Segoe UI", 13, "bold"),
            text_color="#22C55E",
            cursor="hand2"
        )
        self.status_badge.pack(anchor="e")
        self.status_badge.bind("<Button-1>", self._on_badge_click)

        self.status_subtext = ctk.CTkLabel(
            self.header_frame,
            text="0 Critical | 0 Warnings",
            font=("Segoe UI", 10),
            text_color="#A0A0A0",
            cursor="hand2"
        )
        self.status_subtext.pack(anchor="e", pady=(2, 0))
        self.status_subtext.bind("<Button-1>", self._on_badge_click)

        self.version_label = ctk.CTkLabel(
            self.header_frame,
            text=APP_VERSION,
            font=("Segoe UI", 9),
            text_color="#6B7280"
        )
        self.version_label.pack(anchor="e", pady=(8, 0))

        self.refresh_select_row = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.refresh_select_row.pack(anchor="e", pady=(8, 0))

        self.refresh_select_label = ctk.CTkLabel(
            self.refresh_select_row,
            text="Auto Refresh:",
            font=("Segoe UI", 10),
            text_color="#A0A0A0"
        )
        self.refresh_select_label.pack(side="left", padx=(0, 6))

        self.refresh_select = ctk.CTkOptionMenu(
            self.refresh_select_row,
            values=list(REFRESH_INTERVALS_MS.keys()),
            width=70,
            height=24,
            font=("Segoe UI", 10),
            command=self._on_refresh_interval_change
        )
        self.refresh_select.set(DEFAULT_REFRESH_CHOICE)
        self.refresh_select.pack(side="left")

        self.refresh_title = ctk.CTkLabel(
            self.header_frame,
            text="Last Refresh",
            font=("Segoe UI", 10),
            text_color="#A0A0A0"
        )
        self.refresh_title.pack(anchor="e", pady=(8, 0))

        self.refresh_time = ctk.CTkLabel(
            self.header_frame,
            text="--:--:--",
            font=("Segoe UI", 11, "bold"),
            text_color="#E5E7EB"
        )
        self.refresh_time.pack(anchor="e")

        self.refresh_time.configure(text=f"{datetime.datetime.now():%H:%M:%S}")

    # ---------------- Detail-message builders ----------------

    def _defender_detail(self, defender_raw, status):
        if status == "healthy":
            return None
        if defender_raw == "Disabled":
            return (
                "Windows Defender real-time protection is turned off. "
                "Your device may be exposed to malware. Open Windows "
                "Security > Virus & threat protection to turn it back on."
            )
        return (
            "Defender's status couldn't be confirmed. Open Windows "
            "Security to verify real-time protection is enabled."
        )

    def _firewall_detail(self, firewall_raw, status):
        if status == "healthy":
            return None
        if firewall_raw == "Partial":
            return (
                "One or more firewall profiles (Domain, Private, or "
                "Public) are turned off. Enable all profiles in Windows "
                "Defender Firewall settings for full network protection."
            )
        if firewall_raw == "Disabled":
            return (
                "Windows Firewall is completely disabled. Your device is "
                "exposed to unsolicited network connections. Enable it "
                "in Windows Defender Firewall settings immediately."
            )
        return (
            "Firewall status couldn't be confirmed. Open Windows Defender "
            "Firewall settings to check all three network profiles."
        )

    def _bitlocker_detail(self, bitlocker_raw, status):
        if status == "healthy":
            return None
        if bitlocker_raw == "Unprotected":
            return (
                "BitLocker encryption is off on drive C:. If this device "
                "is lost or stolen, the data on it is not protected. "
                "Consider enabling BitLocker via Control Panel > "
                "BitLocker Drive Encryption."
            )
        return (
            "BitLocker status couldn't be verified — this can happen if "
            "the app isn't running as Administrator, or on editions of "
            "Windows without BitLocker support. Check manually via "
            "'Manage BitLocker' in Control Panel."
        )

    def _score_detail(self, score, issues):
        if issues:
            return (
                f"Your security score is {score}/100. This is affected by: "
                f"{', '.join(issues)}. Click each related card above for details."
            )
        return (
            f"Your security score is {score}/100. All monitored security "
            f"checks (Defender, Firewall, BitLocker) are currently passing "
            f"with no issues detected."
        )

    def _metric_detail(self, label, value, status):
        if status == "healthy":
            return None
        if status == "warning":
            return (
                f"{label} is elevated at {value:.0f}%. Consider closing "
                f"unused applications to free up resources."
            )
        return (
            f"{label} is critically high at {value:.0f}%. This can cause "
            f"slowdowns or instability — close unnecessary programs now."
        )

    # ---------------- Card construction ----------------

    def build_cards(self):
        info = get_system_info()
        sec = get_security_info()

        defender_status = "healthy" if sec["Defender"] == "Enabled" else "critical"
        firewall_status = (
            "healthy" if sec["Firewall"] == "Enabled"
            else "warning" if sec["Firewall"] == "Partial"
            else "critical"
        )
        bitlocker_status = "healthy" if sec["BitLocker"] == "Protected" else "critical"
        score_status = (
            "healthy" if sec["Security Score"] >= 85
            else "warning" if sec["Security Score"] >= 60
            else "critical"
        )

        defender_detail = self._defender_detail(sec["Defender"], defender_status)
        firewall_detail = self._firewall_detail(sec["Firewall"], firewall_status)
        bitlocker_detail = self._bitlocker_detail(sec["BitLocker"], bitlocker_status)

        issues = []
        if defender_detail:
            issues.append("Defender")
        if firewall_detail:
            issues.append("Firewall")
        if bitlocker_detail:
            issues.append("BitLocker")
        score_detail = self._score_detail(sec["Security Score"], issues)

        score_value = (
            f'{sec["Security Score"]}/100\n'
            f'Passed: {sec["Passed"]}  |  Warnings: {sec["Warnings"]}  |  Critical: {sec["Critical"]}'
        )

        disk_percent, disk_used_gb, disk_total_gb = get_disk_details()
        storage_value = (
            f'{disk_percent:.0f}%\n'
            f'{disk_used_gb} GB / {disk_total_gb} GB'
        )

        ip_value = f'{info["IP Address"]}\n{info["Network Adapter"]}'

        # (title, value, status, show_progress, detail)
        data = [
            # -- Security --
            ("🛡 Defender", sec["Defender Label"], defender_status, False, defender_detail),
            ("🔥 Firewall", sec["Firewall Label"], firewall_status, False, firewall_detail),
            ("🔒 BitLocker", sec["BitLocker Label"], bitlocker_status, False, bitlocker_detail),
            ("⭐ Security Score", score_value, score_status, True, score_detail),

            # -- System identity --
            ("🖥 Host Name", info["Computer Name"], None, False, None),
            ("👤 Logged-in User", info["Current User"], None, False, None),
            ("🪟 Operating System", info["Windows Edition"], None, False, None),
            ("📦 Release", info["Windows Version"], None, False, None),

            ("🔨 Build", info["Windows Build"], None, False, None),
            ("💻 CPU Model", info["Processor"], None, False, None),
            ("🌐 Local IP", ip_value, None, False, None),
            ("⏱ System Uptime", info["Uptime"], None, False, None),

            # -- Live metrics (status/detail refreshed every 2s) --
            ("⚙ CPU Usage", "--%", "healthy", True, None),
            ("🧠 Memory Usage", "--%", "healthy", True, None),
            ("💽 Disk Activity", "--%", "healthy", True, None),
            ("💾 Storage Used", storage_value, None, True, None),
        ]

        row = 1
        col = 0

        # Cards that should always be clickable, even in a healthy state.
        force_clickable_titles = {"⭐ Security Score"}

        for title, value, status, progress, detail in data:
            card = InfoCard(
                self,
                title=title,
                value=str(value),
                status=status,
                show_progress=progress,
                detail=detail,
                force_clickable=title in force_clickable_titles
            )

            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            self.cards[title] = card

            col += 1
            if col == COLUMNS:
                col = 0
                row += 1

        # Security Score progress bar is a one-time value (not part of the
        # live 2s refresh loop), so set it right after creation.
        self.cards["⭐ Security Score"].set_progress(sec["Security Score"])

        self._security_snapshot = sec  # cached for the badge calc below
        self._last_scan_time = datetime.datetime.now()
        self.update_status_badge_from_all(defender_status, firewall_status,
                                           bitlocker_status, score_status, [])

    def build_footer(self):
        self.footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.footer_frame.grid(
            row=5, column=0, columnspan=COLUMNS,
            sticky="ew", padx=20, pady=(4, 12)
        )

        scan_text = (
            f"Last Scan: {self._last_scan_time:%H:%M:%S}"
            if self._last_scan_time else "Last Scan: --:--:--"
        )

        self.last_scan_label = ctk.CTkLabel(
            self.footer_frame,
            text=scan_text,
            font=("Segoe UI", 10),
            text_color="#9CA3AF"
        )
        self.last_scan_label.pack(side="left")

        self.last_updated_label = ctk.CTkLabel(
            self.footer_frame,
            text="Last Updated: --:--:--",
            font=("Segoe UI", 10),
            text_color="#9CA3AF"
        )
        self.last_updated_label.pack(side="right")

    # ---------------- Status badge / issue summary ----------------

    def get_active_issues(self):
        """Collect (title, status, detail) for every card currently in a
        warning or critical state, in on-screen order."""
        issues = []
        for card in self.cards.values():
            if card._status in ("warning", "critical") and card._detail:
                issues.append((card._display_title, card._status, card._detail))
        return issues

    def _on_badge_click(self, event=None):
        self._show_issues_popup()

    def _show_issues_popup(self):
        issues = self.get_active_issues()
        critical_count = sum(1 for _, s, _ in issues if s == "critical")
        warning_count = sum(1 for _, s, _ in issues if s == "warning")

        popup = ctk.CTkToplevel(self)
        popup.title("Issue Summary")
        popup.geometry("460x360")
        popup.resizable(False, False)

        popup.transient(self.winfo_toplevel())
        popup.lift()
        popup.focus_force()
        popup.grab_set()

        try:
            popup.attributes("-topmost", True)
            popup.after(100, lambda: popup.attributes("-topmost", False))
        except Exception:
            pass

        if not issues:
            header_text, header_color = "✅ All Systems Healthy", STATUS_COLORS["healthy"]
        elif critical_count > 0:
            header_text = f"🔴 {critical_count} Critical | {warning_count} Warnings"
            header_color = STATUS_COLORS["critical"]
        else:
            header_text = f"🟠 {warning_count} Warnings"
            header_color = STATUS_COLORS["warning"]

        header = ctk.CTkLabel(
            popup,
            text=header_text,
            font=("Segoe UI", 15, "bold"),
            text_color=header_color
        )
        header.pack(anchor="w", padx=18, pady=(18, 8))

        if not issues:
            body = ctk.CTkLabel(
                popup,
                text="No active warnings or critical issues detected.",
                wraplength=400,
                justify="left"
            )
            body.pack(anchor="w", padx=18)
        else:
            scroll = ctk.CTkScrollableFrame(popup, width=410, height=230)
            scroll.pack(padx=18, pady=(0, 10), fill="both", expand=True)

            for title, status, detail in issues:
                color = STATUS_COLORS.get(status, "#9CA3AF")
                icon = "🛑" if status == "critical" else "⚠"

                row_title = ctk.CTkLabel(
                    scroll,
                    text=f"{icon} {title}",
                    font=("Segoe UI", 12, "bold"),
                    text_color=color,
                    anchor="w"
                )
                row_title.pack(anchor="w", pady=(6, 0), fill="x")

                row_detail = ctk.CTkLabel(
                    scroll,
                    text=detail,
                    wraplength=380,
                    justify="left",
                    anchor="w",
                    font=("Segoe UI", 10)
                )
                row_detail.pack(anchor="w", pady=(0, 6), fill="x")

        ctk.CTkButton(
            popup,
            text="Close",
            command=popup.destroy
        ).pack(pady=(0, 16))

    # ---------------- Auto refresh interval ----------------

    def _on_refresh_interval_change(self, choice):
        self.refresh_interval_ms = REFRESH_INTERVALS_MS.get(choice, 2000)

        # Apply immediately: cancel whatever refresh is currently pending
        # and kick off a fresh cycle on the new cadence right away.
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None

        self.update_live()

    def get_status(self, value):
        if value < 60:
            return "healthy"
        if value < 85:
            return "warning"
        return "critical"

    def update_status_badge_from_all(self, defender_status, firewall_status,
                                      bitlocker_status, score_status, metric_statuses):
        all_statuses = [
            defender_status, firewall_status, bitlocker_status, score_status
        ] + metric_statuses

        critical_count = all_statuses.count("critical")
        warning_count = all_statuses.count("warning")

        if critical_count > 0:
            self.status_badge.configure(text="🔴 System Critical", text_color="#EF4444")
        elif warning_count > 0:
            self.status_badge.configure(text="🟠 System Warning", text_color="#F59E0B")
        else:
            self.status_badge.configure(text="🟢 System Healthy", text_color="#22C55E")

        self.status_subtext.configure(
            text=f"{critical_count} Critical | {warning_count} Warnings"
        )

    def update_live(self):
        metrics = {
            "⚙ CPU Usage": ("CPU usage", get_cpu_usage()),
            "🧠 Memory Usage": ("Memory usage", get_ram_usage()),
            "💽 Disk Activity": ("Disk activity", get_disk_activity()),
        }

        try:
            percent, used_gb, total_gb = get_disk_details()
            self.cards["💾 Storage Used"].update_value(
                f"{percent:.0f}%\n{used_gb} GB / {total_gb} GB"
            )
            self.cards["💾 Storage Used"].set_progress(percent)
        except Exception:
            self.cards["💾 Storage Used"].update_value(f"{get_disk_usage():.0f}%")

        metric_statuses = []
        for name, (label, value) in metrics.items():
            status = self.get_status(value)
            metric_statuses.append(status)
            detail = self._metric_detail(label, value, status)

            self.cards[name].update_value(f"{value:.0f}%")
            self.cards[name].update_status(status)
            self.cards[name].update_detail(detail)
            self.cards[name].set_progress(value)

        sec = self._security_snapshot
        defender_status = "healthy" if sec["Defender"] == "Enabled" else "critical"
        firewall_status = (
            "healthy" if sec["Firewall"] == "Enabled"
            else "warning" if sec["Firewall"] == "Partial"
            else "critical"
        )
        bitlocker_status = "healthy" if sec["BitLocker"] == "Protected" else "critical"
        score_status = (
            "healthy" if sec["Security Score"] >= 85
            else "warning" if sec["Security Score"] >= 60
            else "critical"
        )

        self.update_status_badge_from_all(
            defender_status, firewall_status, bitlocker_status,
            score_status, metric_statuses
        )

        self.refresh_time.configure(text=f"{datetime.datetime.now():%H:%M:%S}")

        if hasattr(self, "last_updated_label"):
            self.last_updated_label.configure(
                text=f"Last Updated: {datetime.datetime.now():%H:%M:%S}"
            )

        self._refresh_job = self.after(self.refresh_interval_ms, self.update_live)
