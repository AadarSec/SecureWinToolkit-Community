import os
import platform
import subprocess

import customtkinter as ctk
from tkinter import messagebox

from src.services import report_generator
from src.services import scheduler_service


def os_open_folder(path):
    """Opens a folder in the OS's default file explorer."""
    system = platform.system()
    if system == "Windows":
        os.startfile(path)  # noqa: only ever runs on Windows in prod
    elif system == "Darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


# ---------------------------------------------------------------------------
# Color palette (matches SecureWin Toolkit dark theme)
# ---------------------------------------------------------------------------
BG_MAIN        = "#141414"
BG_CARD        = "#1E1E1E"
BG_CARD_ALT    = "#1A1A1A"
BORDER         = "#2A2A2A"

RED            = "#B91C1C"
RED_HOVER      = "#A40000"
RED_TINT_BG    = "#2A1518"
RED_ICON_BG    = "#3B1113"

GREEN          = "#22C55E"
GREEN_ICON_BG  = "#0F2A1D"

BLUE           = "#4EA8FF"
BLUE_ICON_BG   = "#0F2333"

ORANGE         = "#F59E0B"
ORANGE_ICON_BG = "#3A2A0D"

TEXT_PRIMARY   = "#F5F5F5"
TEXT_MUTED     = "#9CA3AF"
TEXT_SUBTLE    = "#6B7280"


# ---------------------------------------------------------------------------
# Placeholder data — replace with real data once functions are mapped.
# ---------------------------------------------------------------------------
RECENT_REPORTS_PLACEHOLDER = [
    {"id": 1, "name": "Windows Audit Report", "type": "PDF", "date": "11 Jul 2025", "time": "10:35 AM", "size": "2.4 MB", "status": "Completed"},
    {"id": 2, "name": "Network Audit Report", "type": "PDF", "date": "11 Jul 2025", "time": "09:15 AM", "size": "1.8 MB", "status": "Completed"},
    {"id": 3, "name": "Windows Audit Report", "type": "PDF", "date": "10 Jul 2025", "time": "04:20 PM", "size": "2.1 MB", "status": "Completed"},
    {"id": 4, "name": "Network Audit Report", "type": "HTML", "date": "10 Jul 2025", "time": "02:10 PM", "size": "3.7 MB", "status": "Completed"},
]

SCHEDULED_REPORTS_PLACEHOLDER = [
    {"id": 1, "name": "Weekly Windows Audit", "audit_type": "Windows Audit", "format": "PDF",
     "schedule": "Every Monday 09:00 AM", "next_run": "14 Jul 2025  09:00 AM", "enabled": True},
]

FILE_TYPE_COLORS = {
    "PDF":  RED,
    "HTML": BLUE,
    "CSV":  GREEN,
    "JSON": ORANGE,
}


class ReportsPage(ctk.CTkFrame):
    """
    Reports section content.
    Meant to be embedded inside the main app's content area
    (to the right of the persistent sidebar).

    Deliberately very compact, single-screen layout with no scrollbar —
    sized to comfortably survive CustomTkinter's automatic DPI scaling
    (e.g. Windows set to 125%/150% display scale) without the bottom of
    the page (Scheduled Reports) being pushed off-screen.

    UI ONLY for now — all data is placeholder and every action
    method is a stub with a TODO. Wire these up to real logic later:

        - on_generate_report()
        - refresh_stats() / refresh_recent_reports() / refresh_scheduled_reports()
        - download_report(report_id)
        - view_report(report_id)
        - add_schedule() / edit_schedule(id) / delete_schedule(id)
        - toggle_schedule(id, enabled)
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_MAIN, **kwargs)

        self.selected_audit_type = ctk.StringVar(value="windows")
        self.selected_format = ctk.StringVar(value="PDF")

        self.opt_include_passed = ctk.BooleanVar(value=True)
        self.opt_include_recommendations = ctk.BooleanVar(value=True)
        self.opt_include_system_info = ctk.BooleanVar(value=True)
        self.opt_executive_summary_only = ctk.BooleanVar(value=False)

        self._audit_type_frames = {}
        self._format_frames = {}

        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_stat_cards()
        self._build_middle_section()
        self._build_scheduled_reports()

        # Pull in whatever has actually been generated before (real data,
        # persisted on disk), instead of the placeholder constants.
        self.refresh_stats()
        self.refresh_recent_reports(report_generator.load_report_index()[:6])

        # Background scheduler: idempotent, safe even if this page gets
        # rebuilt (e.g. user navigates away and back).
        scheduler_service.on_auto_run = self._on_schedule_auto_run
        scheduler_service.start_scheduler()
        self.refresh_scheduled_reports(scheduler_service.load_schedules())

    # ------------------------------------------------------------------ #
    # Header
    # ------------------------------------------------------------------ #
    def _build_header(self):

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(10, 6))

        ctk.CTkLabel(
            header, text="\U0001F4C4  Reports",
            font=("Segoe UI", 18, "bold"),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            header, text="Generate, view and export security audit reports",
            font=("Segoe UI", 10),
            text_color=TEXT_MUTED
        ).pack(anchor="w")

    # ------------------------------------------------------------------ #
    # Top stat cards
    # ------------------------------------------------------------------ #
    def _build_stat_cards(self):

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 8))
        for i in range(4):
            row.grid_columnconfigure(i, weight=1, uniform="stat")

        self.card_total_reports = self._stat_card(
            row, col=0, icon="\U0001F4C4", icon_bg=RED_ICON_BG, icon_color=RED,
            title="Total Reports", value="12", subtitle="All time generated"
        )

        self.card_windows_reports = self._stat_card(
            row, col=1, icon="\u2705", icon_bg=GREEN_ICON_BG, icon_color=GREEN,
            title="Windows Audit Reports", value="7", subtitle="Last 30 days"
        )

        self.card_network_reports = self._stat_card(
            row, col=2, icon="\U0001F310", icon_bg=BLUE_ICON_BG, icon_color=BLUE,
            title="Network Audit Reports", value="5", subtitle="Last 30 days"
        )

        self.card_last_report = self._stat_card(
            row, col=3, icon="\U0001F4C5", icon_bg=ORANGE_ICON_BG, icon_color=ORANGE,
            title="Last Report Generated", value="11 Jul 2025", subtitle="10:35 AM"
        )

    def _stat_card(self, parent, col, icon, icon_bg, icon_color, title, value, subtitle):

        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER)
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=10, pady=8)

        icon_circle = ctk.CTkFrame(inner, fg_color=icon_bg, width=26, height=26, corner_radius=13)
        icon_circle.pack(anchor="w")
        icon_circle.pack_propagate(False)
        ctk.CTkLabel(icon_circle, text=icon, font=("Segoe UI", 11), text_color=icon_color).place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=title, font=("Segoe UI", 10), text_color=TEXT_MUTED).pack(anchor="w", pady=(4, 0))
        value_label = ctk.CTkLabel(inner, text=value, font=("Segoe UI", 15, "bold"), text_color=TEXT_PRIMARY)
        value_label.pack(anchor="w")
        subtitle_label = ctk.CTkLabel(inner, text=subtitle, font=("Segoe UI", 9), text_color=TEXT_SUBTLE)
        subtitle_label.pack(anchor="w")

        return {"card": card, "value_label": value_label, "subtitle_label": subtitle_label}

    # ------------------------------------------------------------------ #
    # Middle section: Generate New Report (left) + Recent Reports (right)
    # ------------------------------------------------------------------ #
    def _build_middle_section(self):

        section = ctk.CTkFrame(self, fg_color="transparent")
        section.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 8))
        section.grid_columnconfigure(0, weight=3)
        section.grid_columnconfigure(1, weight=2)
        section.grid_rowconfigure(0, weight=1)

        self._build_generate_panel(section)
        self._build_recent_reports_panel(section)

    # ---- Generate New Report panel ----
    def _build_generate_panel(self, parent):

        panel = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=10, pady=8)

        ctk.CTkLabel(inner, text="Generate New Report", font=("Segoe UI", 12, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(inner, text="Select audit type and report format", font=("Segoe UI", 10), text_color=TEXT_MUTED).pack(anchor="w", pady=(0, 6))

        # Audit type cards
        audit_row = ctk.CTkFrame(inner, fg_color="transparent")
        audit_row.pack(fill="x", pady=(0, 6))
        audit_row.grid_columnconfigure(0, weight=1)
        audit_row.grid_columnconfigure(1, weight=1)

        self._audit_type_frames["windows"] = self._audit_type_card(
            audit_row, col=0, key="windows", icon="\U0001F5A5",
            title="Windows Audit Report", desc="Windows security audit"
        )
        self._audit_type_frames["network"] = self._audit_type_card(
            audit_row, col=1, key="network", icon="\U0001F310",
            title="Network Audit Report", desc="Network security audit"
        )
        self._refresh_audit_type_selection()

        # Report format
        ctk.CTkLabel(inner, text="Select Report Format", font=("Segoe UI", 11, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", pady=(0, 4))

        fmt_row = ctk.CTkFrame(inner, fg_color="transparent")
        fmt_row.pack(fill="x", pady=(0, 6))
        for i in range(4):
            fmt_row.grid_columnconfigure(i, weight=1, uniform="fmt")

        formats = [
            ("PDF", "\U0001F4C4", "Recommended"),
            ("HTML", "\U0001F4CA", "Web Report"),
            ("CSV", "\U0001F5C2", "Data Export"),
            ("JSON", "{ }", "Raw Data"),
        ]
        for i, (fmt, icon, sub) in enumerate(formats):
            self._format_frames[fmt] = self._format_card(fmt_row, col=i, fmt=fmt, icon=icon, subtitle=sub)
        self._refresh_format_selection()

        # Report options
        ctk.CTkLabel(inner, text="Report Options", font=("Segoe UI", 11, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", pady=(0, 4))

        opts_row = ctk.CTkFrame(inner, fg_color="transparent")
        opts_row.pack(fill="x")

        ctk.CTkCheckBox(opts_row, text="Include Passed Items", variable=self.opt_include_passed,
                         font=("Segoe UI", 10), checkbox_width=14, checkbox_height=14,
                         fg_color=RED, hover_color=RED_HOVER).pack(side="left", padx=(0, 12))
        ctk.CTkCheckBox(opts_row, text="Include Recommendations", variable=self.opt_include_recommendations,
                         font=("Segoe UI", 10), checkbox_width=14, checkbox_height=14,
                         fg_color=RED, hover_color=RED_HOVER).pack(side="left", padx=(0, 12))
        ctk.CTkCheckBox(opts_row, text="Include System Info", variable=self.opt_include_system_info,
                         font=("Segoe UI", 10), checkbox_width=14, checkbox_height=14,
                         fg_color=RED, hover_color=RED_HOVER).pack(side="left")

        ctk.CTkCheckBox(inner, text="Executive Summary Only", variable=self.opt_executive_summary_only,
                         font=("Segoe UI", 10), checkbox_width=14, checkbox_height=14,
                         fg_color=RED, hover_color=RED_HOVER).pack(anchor="w", pady=(4, 8))

        # Generate button
        ctk.CTkButton(
            inner, text="\U0001F4C4  Generate Report", height=28,
            font=("Segoe UI", 11, "bold"),
            fg_color=RED, hover_color=RED_HOVER,
            command=self.on_generate_report
        ).pack(fill="x")

    def _audit_type_card(self, parent, col, key, icon, title, desc):

        card = ctk.CTkFrame(parent, fg_color=BG_CARD_ALT, corner_radius=6, border_width=2, border_color=BORDER, cursor="hand2")
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=8, pady=5)

        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")

        icon_circle = ctk.CTkFrame(top, fg_color=RED_ICON_BG, width=22, height=22, corner_radius=11)
        icon_circle.pack(side="left")
        icon_circle.pack_propagate(False)
        ctk.CTkLabel(icon_circle, text=icon, font=("Segoe UI", 10), text_color=RED).place(relx=0.5, rely=0.5, anchor="center")

        radio = ctk.CTkFrame(top, fg_color="transparent", width=14, height=14)
        radio.pack(side="right")
        radio.pack_propagate(False)
        radio_dot = ctk.CTkFrame(radio, fg_color=BG_MAIN, width=14, height=14, corner_radius=7, border_width=2, border_color=TEXT_SUBTLE)
        radio_dot.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=title, font=("Segoe UI", 11, "bold"), text_color=TEXT_PRIMARY, justify="left").pack(anchor="w", pady=(4, 0))
        ctk.CTkLabel(inner, text=desc, font=("Segoe UI", 9), text_color=TEXT_MUTED, justify="left").pack(anchor="w")

        widgets = [card, inner, top, icon_circle]
        for w in widgets:
            w.bind("<Button-1>", lambda e, k=key: self._select_audit_type(k))

        return {"card": card, "radio_dot": radio_dot}

    def _select_audit_type(self, key):
        self.selected_audit_type.set(key)
        self._refresh_audit_type_selection()

    def _refresh_audit_type_selection(self):
        for key, refs in self._audit_type_frames.items():
            selected = (key == self.selected_audit_type.get())
            refs["card"].configure(
                border_color=RED if selected else BORDER,
                fg_color=RED_TINT_BG if selected else BG_CARD_ALT,
            )
            refs["radio_dot"].configure(
                fg_color=RED if selected else BG_MAIN,
                border_color=RED if selected else TEXT_SUBTLE,
            )

    def _format_card(self, parent, col, fmt, icon, subtitle):

        card = ctk.CTkFrame(parent, fg_color=BG_CARD_ALT, corner_radius=6, border_width=1, border_color=BORDER, cursor="hand2")
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 5, 0))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=4, pady=5)

        icon_label = ctk.CTkLabel(inner, text=icon, font=("Segoe UI", 13), text_color=TEXT_PRIMARY)
        icon_label.pack()

        name_label = ctk.CTkLabel(inner, text=fmt, font=("Segoe UI", 11, "bold"), text_color=TEXT_PRIMARY)
        name_label.pack(pady=(2, 0))

        sub_label = ctk.CTkLabel(inner, text=subtitle, font=("Segoe UI", 8), text_color=TEXT_MUTED)
        sub_label.pack()

        widgets = [card, inner, icon_label, name_label, sub_label]
        for w in widgets:
            w.bind("<Button-1>", lambda e, f=fmt: self._select_format(f))

        return {"card": card, "icon_label": icon_label, "name_label": name_label, "sub_label": sub_label}

    def _select_format(self, fmt):
        self.selected_format.set(fmt)
        self._refresh_format_selection()

    def _refresh_format_selection(self):
        for fmt, refs in self._format_frames.items():
            selected = (fmt == self.selected_format.get())
            refs["card"].configure(
                fg_color=RED if selected else BG_CARD_ALT,
                border_color=RED if selected else BORDER,
            )
            text_color = "#FFFFFF" if selected else TEXT_PRIMARY
            muted_color = "#FFD9D9" if selected else TEXT_MUTED
            refs["icon_label"].configure(text_color=text_color)
            refs["name_label"].configure(text_color=text_color)
            refs["sub_label"].configure(text_color=muted_color)

    # ---- Recent Reports panel ----
    def _build_recent_reports_panel(self, parent):

        panel = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER)
        panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=8, pady=8)

        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")
        ctk.CTkLabel(top, text="Recent Reports", font=("Segoe UI", 12, "bold"), text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkButton(
            top, text="View All", width=55, height=18, fg_color="transparent",
            hover_color=BG_CARD_ALT, text_color=RED, font=("Segoe UI", 9, "bold"),
            command=self.on_view_all_reports
        ).pack(side="right")

        self.recent_reports_list = ctk.CTkScrollableFrame(inner, fg_color="transparent", height=185)
        self.recent_reports_list.pack(fill="both", expand=True, pady=(6, 0))

        self.refresh_recent_reports([])

    def refresh_recent_reports(self, reports):
        """Rebuild the recent-reports list. Call this with real data later."""

        for child in self.recent_reports_list.winfo_children():
            child.destroy()

        if not reports:
            ctk.CTkLabel(
                self.recent_reports_list,
                text="No reports generated yet.\nUse the panel on the left to create one.",
                font=("Segoe UI", 10), text_color=TEXT_MUTED, justify="center"
            ).pack(pady=20)
            return

        for report in reports:
            self._recent_report_row(self.recent_reports_list, report)

    def _recent_report_row(self, parent, report):

        row = ctk.CTkFrame(parent, fg_color=BG_CARD_ALT, corner_radius=6)
        row.pack(fill="x", pady=2)

        inner = ctk.CTkFrame(row, fg_color="transparent")
        inner.pack(fill="x", padx=6, pady=4)
        inner.grid_columnconfigure(1, weight=1)

        color = FILE_TYPE_COLORS.get(report["type"], TEXT_MUTED)
        icon_box = ctk.CTkFrame(inner, fg_color=color, width=24, height=24, corner_radius=5)
        icon_box.grid(row=0, column=0, rowspan=2, padx=(0, 6))
        icon_box.grid_propagate(False)
        ctk.CTkLabel(icon_box, text=report["type"], font=("Segoe UI", 7, "bold"), text_color="#FFFFFF").place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=report["name"], font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            inner, text=f'{report["date"]}  \u2022  {report["size"]}',
            font=("Segoe UI", 8), text_color=TEXT_MUTED
        ).grid(row=1, column=1, sticky="w")

        actions = ctk.CTkFrame(inner, fg_color="transparent")
        actions.grid(row=0, column=2, rowspan=2, sticky="e")

        status_badge = ctk.CTkLabel(
            actions, text=report["status"], font=("Segoe UI", 8, "bold"),
            text_color=GREEN, fg_color=GREEN_ICON_BG, corner_radius=8, width=58, height=16
        )
        status_badge.pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            actions, text="\u2B07", width=20, height=20, fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT_PRIMARY, font=("Segoe UI", 9),
            command=lambda rid=report["id"]: self.download_report(rid)
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            actions, text="\U0001F441", width=20, height=20, fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT_PRIMARY, font=("Segoe UI", 9),
            command=lambda rid=report["id"]: self.view_report(rid)
        ).pack(side="left")

    # ------------------------------------------------------------------ #
    # Scheduled Reports
    # ------------------------------------------------------------------ #
    def _build_scheduled_reports(self):

        panel = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER)
        panel.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 10))

        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=10, pady=8)

        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")

        text_col = ctk.CTkFrame(top, fg_color="transparent")
        text_col.pack(side="left")
        ctk.CTkLabel(text_col, text="Scheduled Reports", font=("Segoe UI", 12, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(text_col, text="Automatically generate reports at scheduled intervals", font=("Segoe UI", 10), text_color=TEXT_MUTED).pack(anchor="w")

        ctk.CTkButton(
            top, text="+  Add Schedule", width=110, height=24,
            fg_color=RED, hover_color=RED_HOVER, font=("Segoe UI", 10, "bold"),
            command=self.add_schedule
        ).pack(side="right")

        table = ctk.CTkFrame(inner, fg_color="transparent")
        table.pack(fill="both", expand=True, pady=(6, 0))

        columns = ["Report Name", "Audit Type", "Format", "Schedule", "Next Run", "Status", "Actions"]
        weights = [2, 2, 1, 2, 2, 1, 1]
        for i, w in enumerate(weights):
            table.grid_columnconfigure(i, weight=w, uniform="sched")

        for i, col_name in enumerate(columns):
            ctk.CTkLabel(table, text=col_name, font=("Segoe UI", 9, "bold"), text_color=TEXT_MUTED).grid(
                row=0, column=i, sticky="w", pady=(0, 4), padx=(0, 4)
            )

        self.scheduled_reports_table = table
        self._scheduled_row_start = 1
        self.refresh_scheduled_reports([])

    def refresh_scheduled_reports(self, schedules):
        """Rebuild the scheduled-reports table. Call this with real data later."""

        for child in self.scheduled_reports_table.winfo_children():
            info = child.grid_info()
            if info and int(info["row"]) >= self._scheduled_row_start:
                child.destroy()

        if not schedules:
            ctk.CTkLabel(
                self.scheduled_reports_table,
                text="No scheduled reports yet. Click \"Add Schedule\" to automate report generation.",
                font=("Segoe UI", 10), text_color=TEXT_MUTED
            ).grid(row=self._scheduled_row_start, column=0, columnspan=7, sticky="w", pady=8)
            return

        for r, sched in enumerate(schedules, start=self._scheduled_row_start):
            self._scheduled_row(self.scheduled_reports_table, r, sched)

    AUDIT_TYPE_LABELS = {"windows": "Windows Audit", "network": "Network Audit"}

    def _scheduled_row(self, table, row_idx, sched):

        import datetime as _dt

        ctk.CTkLabel(table, text=sched["name"], font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).grid(
            row=row_idx, column=0, sticky="w", pady=3
        )
        ctk.CTkLabel(
            table, text=self.AUDIT_TYPE_LABELS.get(sched["audit_type"], sched["audit_type"]),
            font=("Segoe UI", 10), text_color=TEXT_MUTED
        ).grid(row=row_idx, column=1, sticky="w")
        ctk.CTkLabel(table, text=sched["format"], font=("Segoe UI", 10), text_color=TEXT_MUTED).grid(
            row=row_idx, column=2, sticky="w"
        )
        ctk.CTkLabel(table, text=sched["schedule_label"], font=("Segoe UI", 10), text_color=TEXT_MUTED).grid(
            row=row_idx, column=3, sticky="w"
        )

        try:
            next_run_dt = _dt.datetime.fromisoformat(sched["next_run"])
            next_run_text = next_run_dt.strftime("%d %b %Y, %I:%M %p")
        except (KeyError, ValueError):
            next_run_text = "-"

        ctk.CTkLabel(table, text=next_run_text, font=("Segoe UI", 10), text_color=TEXT_MUTED).grid(
            row=row_idx, column=4, sticky="w"
        )

        switch_var = ctk.BooleanVar(value=sched["enabled"])
        ctk.CTkSwitch(
            table, text="", variable=switch_var, width=28, progress_color=GREEN,
            command=lambda sid=sched["id"], v=switch_var: self.toggle_schedule(sid, v.get())
        ).grid(row=row_idx, column=5, sticky="w")

        actions = ctk.CTkFrame(table, fg_color="transparent")
        actions.grid(row=row_idx, column=6, sticky="w")
        ctk.CTkButton(
            actions, text="\u270F", width=20, height=20, fg_color=BG_CARD_ALT, hover_color=BORDER,
            text_color=TEXT_PRIMARY, font=("Segoe UI", 9),
            command=lambda sid=sched["id"]: self.edit_schedule(sid)
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            actions, text="\U0001F5D1", width=20, height=20, fg_color=BG_CARD_ALT, hover_color=RED_TINT_BG,
            text_color=RED, font=("Segoe UI", 9),
            command=lambda sid=sched["id"]: self.delete_schedule(sid)
        ).pack(side="left")

    def add_schedule(self):
        self._open_schedule_dialog(mode="add")

    def edit_schedule(self, schedule_id):
        sched = next((s for s in scheduler_service.load_schedules() if s["id"] == schedule_id), None)
        if sched is None:
            messagebox.showerror("Not Found", "That schedule no longer exists.")
            return
        self._open_schedule_dialog(mode="edit", sched=sched)

    def delete_schedule(self, schedule_id):
        if not messagebox.askyesno("Delete Schedule", "Remove this scheduled report? This can't be undone."):
            return
        scheduler_service.delete_schedule(schedule_id)
        self.refresh_scheduled_reports(scheduler_service.load_schedules())

    def toggle_schedule(self, schedule_id, enabled):
        scheduler_service.toggle_schedule(schedule_id, enabled)
        self.refresh_scheduled_reports(scheduler_service.load_schedules())

    def _on_schedule_auto_run(self, sched, entry, error):
        """
        Called from the background scheduler thread when a schedule fires.
        We're off the Tk main thread here, so hop back onto it before
        touching any widgets.
        """
        self.after(0, self._handle_schedule_auto_run_ui, sched, entry, error)

    def _handle_schedule_auto_run_ui(self, sched, entry, error):
        if not self.winfo_exists():
            return
        self.refresh_stats()
        self.refresh_recent_reports(report_generator.load_report_index()[:6])
        self.refresh_scheduled_reports(scheduler_service.load_schedules())

    # ------------------------------------------------------------------ #
    # Add / Edit schedule dialog
    # ------------------------------------------------------------------ #
    def _open_schedule_dialog(self, mode, sched=None):

        dialog = ctk.CTkToplevel(self)
        dialog.title("Add Schedule" if mode == "add" else "Edit Schedule")
        dialog.geometry("400x620")
        dialog.minsize(360, 460)
        dialog.configure(fg_color=BG_MAIN)
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        dialog.resizable(False, True)

        # Reserve the button row's space FIRST (packed with side="bottom"
        # before anything else), so it's guaranteed to stay visible even
        # if the window ends up shorter than the field list needs --
        # the scrollable area below simply scrolls instead of pushing
        # the buttons off-screen.
        btn_row = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=16, side="bottom")

        scroll_area = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll_area.pack(fill="both", expand=True, padx=0, pady=0)

        pad = {"padx": 20, "pady": (10, 0)}

        ctk.CTkLabel(scroll_area, text="Report Name", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", **pad)
        name_entry = ctk.CTkEntry(scroll_area, height=30)
        name_entry.pack(fill="x", padx=20, pady=(4, 0))
        name_entry.insert(0, sched["name"] if sched else "Weekly Windows Audit")

        ctk.CTkLabel(scroll_area, text="Audit Type", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", **pad)
        audit_type_var = ctk.StringVar(value="Windows Audit" if not sched or sched["audit_type"] == "windows" else "Network Audit")
        ctk.CTkOptionMenu(scroll_area, values=["Windows Audit", "Network Audit"], variable=audit_type_var,
                           fg_color=BG_CARD_ALT, button_color=RED, button_hover_color=RED_HOVER).pack(fill="x", padx=20, pady=(4, 0))

        ctk.CTkLabel(scroll_area, text="Format", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", **pad)
        format_var = ctk.StringVar(value=sched["format"] if sched else "PDF")
        ctk.CTkOptionMenu(scroll_area, values=["PDF", "HTML", "CSV", "JSON"], variable=format_var,
                           fg_color=BG_CARD_ALT, button_color=RED, button_hover_color=RED_HOVER).pack(fill="x", padx=20, pady=(4, 0))

        ctk.CTkLabel(scroll_area, text="Frequency", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", **pad)
        frequency_var = ctk.StringVar(value=sched["frequency"] if sched else "Weekly")
        ctk.CTkOptionMenu(scroll_area, values=["Daily", "Weekly"], variable=frequency_var,
                           fg_color=BG_CARD_ALT, button_color=RED, button_hover_color=RED_HOVER).pack(fill="x", padx=20, pady=(4, 0))

        ctk.CTkLabel(scroll_area, text="Day (for Weekly)", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", **pad)
        from src.services.scheduler_service import WEEKDAYS
        day_var = ctk.StringVar(value=WEEKDAYS[sched["day_of_week"]] if sched else "Monday")
        ctk.CTkOptionMenu(scroll_area, values=WEEKDAYS, variable=day_var,
                           fg_color=BG_CARD_ALT, button_color=RED, button_hover_color=RED_HOVER).pack(fill="x", padx=20, pady=(4, 0))

        ctk.CTkLabel(scroll_area, text="Time (24h, HH:MM)", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", **pad)
        time_entry = ctk.CTkEntry(scroll_area, height=30)
        time_entry.pack(fill="x", padx=20, pady=(4, 0))
        time_entry.insert(0, sched["time"] if sched else "09:00")

        error_label = ctk.CTkLabel(scroll_area, text="", font=("Segoe UI", 9), text_color=RED, wraplength=340, justify="left")
        error_label.pack(anchor="w", padx=20, pady=(8, 12))

        def on_save():
            name = name_entry.get().strip()
            time_str = time_entry.get().strip()

            if not name:
                error_label.configure(text="Report name can't be empty.")
                return

            try:
                hour, minute = map(int, time_str.split(":"))
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError
            except ValueError:
                error_label.configure(text="Time must be in 24h HH:MM format, e.g. 09:00 or 18:30.")
                return

            audit_type = "windows" if audit_type_var.get() == "Windows Audit" else "network"
            day_of_week = WEEKDAYS.index(day_var.get())

            try:
                if mode == "add":
                    scheduler_service.add_schedule(
                        name=name, audit_type=audit_type, fmt=format_var.get(),
                        frequency=frequency_var.get(), day_of_week=day_of_week, time_str=time_str,
                    )
                else:
                    scheduler_service.update_schedule(
                        sched["id"], name=name, audit_type=audit_type, format=format_var.get(),
                        frequency=frequency_var.get(), day_of_week=day_of_week, time=time_str,
                    )
            except Exception as e:
                error_label.configure(text=f"Couldn't save: {e}")
                return

            self.refresh_scheduled_reports(scheduler_service.load_schedules())
            dialog.destroy()

        # btn_row was already packed (side="bottom") before scroll_area,
        # so it's guaranteed to be visible -- just fill it in now.
        ctk.CTkButton(btn_row, text="Cancel", fg_color=BG_CARD_ALT, hover_color=BORDER,
                      text_color=TEXT_PRIMARY, command=dialog.destroy).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(btn_row, text="Save Schedule", fg_color=RED, hover_color=RED_HOVER,
                      command=on_save).pack(side="left", expand=True, fill="x", padx=(6, 0))

    # ------------------------------------------------------------------ #
    # Report generation / download / view / stats
    # ------------------------------------------------------------------ #
    def on_generate_report(self):
        """
        Pulls real scan results out of AuditCache (whatever the user has
        already scanned in Windows Audit / Network Audit) and writes an
        actual PDF/HTML/CSV/JSON report file to disk.
        """

        audit_type = self.selected_audit_type.get()
        fmt = self.selected_format.get()

        options = {
            "include_passed": self.opt_include_passed.get(),
            "include_recommendations": self.opt_include_recommendations.get(),
            "include_system_info": self.opt_include_system_info.get(),
            "executive_summary_only": self.opt_executive_summary_only.get(),
        }

        try:
            entry = report_generator.generate_report(audit_type, fmt, options)
        except ValueError as e:
            # Most common case: no scan has been run yet for that audit type.
            messagebox.showwarning("Can't Generate Report", str(e))
            return
        except Exception as e:
            messagebox.showerror("Report Generation Failed", f"Something went wrong:\n{e}")
            return

        self.refresh_stats()
        self.refresh_recent_reports(report_generator.load_report_index()[:6])

        messagebox.showinfo(
            "Report Generated",
            f"{entry['name']} ({entry['type']}) saved successfully.\n\n{entry['filepath']}"
        )

    def on_view_all_reports(self):
        """Opens the folder where all generated reports live."""
        try:
            os_open_folder(report_generator.REPORTS_DIR)
        except Exception as e:
            messagebox.showerror("Couldn't Open Folder", str(e))

    def download_report(self, report_id):
        """'Download' = reveal the actual file in the OS file explorer."""
        try:
            report_generator.reveal_report(report_id)
        except FileNotFoundError as e:
            messagebox.showerror("File Not Found", str(e))

    def view_report(self, report_id):
        """Opens the report with the system's default viewer for that file type."""
        try:
            report_generator.open_report(report_id)
        except FileNotFoundError as e:
            messagebox.showerror("File Not Found", str(e))

    def refresh_stats(self):
        """Recomputes the 4 top stat cards from the real report index."""

        stats = report_generator.get_report_stats()

        self.card_total_reports["value_label"].configure(text=str(stats["total_reports"]))

        self.card_windows_reports["value_label"].configure(text=str(stats["windows_reports"]))

        self.card_network_reports["value_label"].configure(text=str(stats["network_reports"]))

        self.card_last_report["value_label"].configure(text=stats["last_report_date"])
        self.card_last_report["subtitle_label"].configure(text=stats["last_report_time"])


# ---------------------------------------------------------------------------
# Standalone preview
# (In the real app, ReportsPage gets embedded next to the sidebar nav.)
# ---------------------------------------------------------------------------
if __name__ == "__main__":

    ctk.set_appearance_mode("dark")

    root = ctk.CTk()
    root.title("SecureWin Toolkit - Reports (Preview)")
    root.geometry("1400x820")
    root.configure(fg_color=BG_MAIN)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    page = ReportsPage(root)
    page.grid(row=0, column=0, sticky="nsew")

    root.mainloop()
