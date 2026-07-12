import os
import platform
import subprocess

import customtkinter as ctk
from tkinter import messagebox

from src.services import settings_service
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
# Color palette (matches SecureWin Toolkit dark theme -- same as Reports)
# ---------------------------------------------------------------------------
BG_MAIN        = "#141414"
BG_CARD        = "#1E1E1E"
BG_CARD_ALT    = "#1A1A1A"
BORDER         = "#2A2A2A"

RED            = "#B91C1C"
RED_HOVER      = "#A40000"
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

APP_VERSION = "1.0.0"


class SettingsPage(ctk.CTkFrame):
    """
    Settings section content. Every control here reads from / writes to
    settings_service (persisted at ~/SecureWinToolkit/settings.json), and
    the ones with real downstream effects (scheduler on/off + interval,
    report defaults, auto-open) actually change app behavior immediately
    -- nothing here is just for show.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_MAIN, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self._render()

    def _render(self):

        self.settings = settings_service.load_settings()
        self.bool_vars = {}

        self._build_header()

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))
        body.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_report_defaults_section(body, row=0)
        self._build_behavior_section(body, row=1)
        self._build_scheduler_section(body, row=2)
        self._build_data_section(body, row=3)
        self._build_about_section(body, row=4)

    # ------------------------------------------------------------------ #
    # Header
    # ------------------------------------------------------------------ #
    def _build_header(self):

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(10, 6))

        ctk.CTkLabel(
            header, text="\u2699\ufe0f  Settings",
            font=("Segoe UI", 18, "bold"),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            header, text="Configure scanning, reports and scheduler behavior",
            font=("Segoe UI", 10),
            text_color=TEXT_MUTED
        ).pack(anchor="w")

    # ------------------------------------------------------------------ #
    # Shared card / row helpers
    # ------------------------------------------------------------------ #
    def _section_card(self, parent, row, icon, icon_bg, icon_color, title, subtitle):

        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 14))
        card.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 4))

        icon_box = ctk.CTkFrame(head, fg_color=icon_bg, width=32, height=32, corner_radius=8)
        icon_box.pack(side="left", padx=(0, 10))
        icon_box.pack_propagate(False)
        ctk.CTkLabel(icon_box, text=icon, font=("Segoe UI", 14), text_color=icon_color).place(relx=0.5, rely=0.5, anchor="center")

        text_col = ctk.CTkFrame(head, fg_color="transparent")
        text_col.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(text_col, text=title, font=("Segoe UI", 13, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(text_col, text=subtitle, font=("Segoe UI", 9), text_color=TEXT_SUBTLE).pack(anchor="w")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=18, pady=(6, 16))
        body.grid_columnconfigure(1, weight=1)

        return body

    def _setting_row(self, parent, row, label, description, control_builder):
        """One labeled row inside a section card: label+description on the
        left, an arbitrary control (toggle/dropdown/button) on the right."""

        text_col = ctk.CTkFrame(parent, fg_color="transparent")
        text_col.grid(row=row, column=0, sticky="w", pady=8)
        ctk.CTkLabel(text_col, text=label, font=("Segoe UI", 11), text_color=TEXT_PRIMARY).pack(anchor="w")
        if description:
            ctk.CTkLabel(text_col, text=description, font=("Segoe UI", 9), text_color=TEXT_SUBTLE, wraplength=380, justify="left").pack(anchor="w")

        control_frame = ctk.CTkFrame(parent, fg_color="transparent")
        control_frame.grid(row=row, column=1, sticky="e", pady=8, padx=(10, 0))
        control_builder(control_frame)

    def _divider(self, parent, row):
        line = ctk.CTkFrame(parent, fg_color=BORDER, height=1)
        line.grid(row=row, column=0, columnspan=2, sticky="ew", pady=4)

    def _save(self, key, value):
        self.settings = settings_service.set(key, value)

    # ------------------------------------------------------------------ #
    # 1. Report Defaults
    # ------------------------------------------------------------------ #
    def _build_report_defaults_section(self, parent, row):

        body = self._section_card(
            parent, row, icon="\U0001F4C4", icon_bg=RED_ICON_BG, icon_color=RED,
            title="Report Defaults", subtitle="Pre-selected options when you open the Reports page"
        )

        r = 0

        self.var_audit_type = ctk.StringVar(value="Windows Audit" if self.settings["default_audit_type"] == "windows" else "Network Audit")

        def build_audit_type(cf):
            def on_change(choice):
                self._save("default_audit_type", "windows" if choice == "Windows Audit" else "network")

            ctk.CTkOptionMenu(cf, values=["Windows Audit", "Network Audit"], variable=self.var_audit_type, width=160,
                               fg_color=BG_CARD_ALT, button_color=RED, button_hover_color=RED_HOVER,
                               command=on_change).pack()

        self._setting_row(body, r, "Default Audit Type", "Which audit type is selected by default", build_audit_type); r += 1
        self._divider(body, r); r += 1

        self.var_format = ctk.StringVar(value=self.settings["default_report_format"])

        def build_format(cf):
            def on_change(choice):
                self._save("default_report_format", choice)

            ctk.CTkOptionMenu(cf, values=["PDF", "HTML", "CSV", "JSON"], variable=self.var_format, width=160,
                               fg_color=BG_CARD_ALT, button_color=RED, button_hover_color=RED_HOVER,
                               command=on_change).pack()

        self._setting_row(body, r, "Default Report Format", "Format pre-selected when generating a new report", build_format); r += 1
        self._divider(body, r); r += 1

        def build_toggle(key):
            def _builder(cf):
                var = ctk.BooleanVar(value=self.settings[key])
                self.bool_vars[key] = var
                ctk.CTkSwitch(cf, text="", variable=var, width=40, progress_color=RED,
                              command=lambda: self._save(key, var.get())).pack()
            return _builder

        self._setting_row(body, r, "Include Passed Items", "Show checks that passed, not just warnings/critical", build_toggle("include_passed_by_default")); r += 1
        self._divider(body, r); r += 1
        self._setting_row(body, r, "Include Recommendations", "Add the fix/recommendation text for each check", build_toggle("include_recommendations_by_default")); r += 1
        self._divider(body, r); r += 1
        self._setting_row(body, r, "Include System Info", "Add system information section to generated reports", build_toggle("include_system_info_by_default")); r += 1

    # ------------------------------------------------------------------ #
    # 2. Behavior
    # ------------------------------------------------------------------ #
    def _build_behavior_section(self, parent, row):

        body = self._section_card(
            parent, row, icon="\U0001F5B1\ufe0f", icon_bg=BLUE_ICON_BG, icon_color=BLUE,
            title="Behavior", subtitle="How the app reacts to your actions"
        )

        r = 0

        def build_auto_open(cf):
            var = ctk.BooleanVar(value=self.settings["auto_open_report_after_generate"])
            self.bool_vars["auto_open_report_after_generate"] = var
            ctk.CTkSwitch(cf, text="", variable=var, width=40, progress_color=RED,
                          command=lambda: self._save("auto_open_report_after_generate", var.get())).pack()

        self._setting_row(body, r, "Auto-Open Report After Generating", "Opens the file automatically once it's created", build_auto_open); r += 1
        self._divider(body, r); r += 1

        def build_confirm(cf):
            var = ctk.BooleanVar(value=self.settings["confirm_before_running_audit"])
            self.bool_vars["confirm_before_running_audit"] = var
            ctk.CTkSwitch(cf, text="", variable=var, width=40, progress_color=RED,
                          command=lambda: self._save("confirm_before_running_audit", var.get())).pack()

        self._setting_row(body, r, "Confirm Before Running Full Audit", "Ask for confirmation before a full scan starts", build_confirm); r += 1

    # ------------------------------------------------------------------ #
    # 3. Scheduler
    # ------------------------------------------------------------------ #
    def _build_scheduler_section(self, parent, row):

        body = self._section_card(
            parent, row, icon="\U0001F551", icon_bg=ORANGE_ICON_BG, icon_color=ORANGE,
            title="Scheduler", subtitle="Background job that auto-generates reports on schedule"
        )

        r = 0

        def build_enabled(cf):
            var = ctk.BooleanVar(value=self.settings["scheduler_enabled"])
            self.bool_vars["scheduler_enabled"] = var

            def on_toggle():
                enabled = var.get()
                self._save("scheduler_enabled", enabled)
                if enabled:
                    scheduler_service.start_scheduler(poll_seconds=self.settings["scheduler_poll_seconds"])
                else:
                    scheduler_service.stop_scheduler()

            ctk.CTkSwitch(cf, text="", variable=var, width=40, progress_color=RED, command=on_toggle).pack()

        self._setting_row(body, r, "Enable Background Scheduler", "Scheduled reports only run while this is on and the app is open", build_enabled); r += 1
        self._divider(body, r); r += 1

        self.var_scheduler_interval = ctk.StringVar(value=str(self.settings["scheduler_poll_seconds"]))

        def build_interval(cf):
            def on_change(*_):
                text = self.var_scheduler_interval.get().strip()
                if text.isdigit() and int(text) >= 5:
                    interval = int(text)
                    self._save("scheduler_poll_seconds", interval)
                    if self.settings["scheduler_enabled"]:
                        scheduler_service.stop_scheduler()
                        scheduler_service.start_scheduler(poll_seconds=interval)

            entry = ctk.CTkEntry(cf, textvariable=self.var_scheduler_interval, width=70, height=28)
            entry.pack(side="left")
            entry.bind("<FocusOut>", on_change)
            entry.bind("<Return>", on_change)
            ctk.CTkLabel(cf, text="seconds", font=("Segoe UI", 9), text_color=TEXT_MUTED).pack(side="left", padx=(6, 0))

        self._setting_row(body, r, "Check Interval", "How often the scheduler checks for due reports (min 5s)", build_interval); r += 1

    # ------------------------------------------------------------------ #
    # 4. Data & Storage
    # ------------------------------------------------------------------ #
    def _build_data_section(self, parent, row):

        body = self._section_card(
            parent, row, icon="\U0001F5C4\ufe0f", icon_bg=GREEN_ICON_BG, icon_color=GREEN,
            title="Data & Storage", subtitle="Where reports are saved and how much space they use"
        )

        info = settings_service.get_storage_info()
        r = 0

        def build_path(cf):
            ctk.CTkButton(
                cf, text="Open Folder", width=110, height=28,
                fg_color=BG_CARD_ALT, hover_color=BORDER, text_color=TEXT_PRIMARY,
                command=lambda: os_open_folder(info["reports_dir"])
            ).pack()

        self._setting_row(body, r, "Reports Folder", info["reports_dir"], build_path); r += 1
        self._divider(body, r); r += 1

        def build_usage(cf):
            self.storage_usage_label = ctk.CTkLabel(cf, text=f"{info['report_count']} files \u00b7 {info['total_size']}",
                        font=("Segoe UI", 10), text_color=TEXT_MUTED)
            self.storage_usage_label.pack()

        self._setting_row(body, r, "Storage Used", "Total size of all generated reports on disk", build_usage); r += 1
        self._divider(body, r); r += 1

        def build_clear(cf):
            ctk.CTkButton(
                cf, text="Clear Report History", width=150, height=28,
                fg_color=RED, hover_color=RED_HOVER, text_color="#FFFFFF",
                command=self._on_clear_history
            ).pack()

        self._setting_row(body, r, "Clear Report History", "Deletes all generated report files and history (cannot be undone)", build_clear); r += 1

    def _on_clear_history(self):

        if not messagebox.askyesno(
            "Clear Report History",
            "This will permanently delete all generated report files and clear the history. Continue?"
        ):
            return

        count = settings_service.clear_report_history(delete_files=True)

        # Surgical update: only the "Storage Used" label changes here.
        # Nothing else on the page is touched, so there's no rebuild/flicker.
        info = settings_service.get_storage_info()
        self.storage_usage_label.configure(text=f"{info['report_count']} files \u00b7 {info['total_size']}")

        messagebox.showinfo("Cleared", f"Removed {count} report(s) from history.")

    # ------------------------------------------------------------------ #
    # 5. About
    # ------------------------------------------------------------------ #
    def _build_about_section(self, parent, row):

        body = self._section_card(
            parent, row, icon="\u2139\ufe0f", icon_bg=BLUE_ICON_BG, icon_color=BLUE,
            title="About", subtitle="SecureWin Toolkit"
        )

        r = 0
        scanner_count = self._get_scanner_count()

        def build_static(text):
            def _builder(cf):
                ctk.CTkLabel(cf, text=text, font=("Segoe UI", 10), text_color=TEXT_MUTED).pack()
            return _builder

        self._setting_row(body, r, "Version", "", build_static(APP_VERSION)); r += 1
        self._divider(body, r); r += 1
        self._setting_row(body, r, "Available Scanners", "Security checks this build can run", build_static(str(scanner_count))); r += 1
        self._divider(body, r); r += 1

        def build_reset(cf):
            ctk.CTkButton(
                cf, text="Reset All Settings", width=150, height=28,
                fg_color=BG_CARD_ALT, hover_color=BORDER, text_color=TEXT_PRIMARY,
                command=self._on_reset_settings
            ).pack()

        self._setting_row(body, r, "Reset All Settings", "Restore every setting on this page to its default value", build_reset); r += 1

    def _get_scanner_count(self):
        try:
            from src.audit.audit_manager import SCANNERS
            return len(SCANNERS)
        except Exception:
            return "-"

    def _on_reset_settings(self):

        if not messagebox.askyesno("Reset Settings", "Restore all settings to their default values?"):
            return

        self.settings = settings_service.reset_to_defaults()

        # Surgical update: push the new default values into the existing
        # controls' variables. No widgets are destroyed or recreated, so
        # there's no visible page rebuild/flicker.
        self.var_audit_type.set("Windows Audit" if self.settings["default_audit_type"] == "windows" else "Network Audit")
        self.var_format.set(self.settings["default_report_format"])
        self.var_scheduler_interval.set(str(self.settings["scheduler_poll_seconds"]))

        for key, var in self.bool_vars.items():
            var.set(self.settings[key])

        # The scheduler's actual running state needs to be re-synced too,
        # not just the switch's visual position.
        if self.settings["scheduler_enabled"]:
            scheduler_service.stop_scheduler()
            scheduler_service.start_scheduler(poll_seconds=self.settings["scheduler_poll_seconds"])
        else:
            scheduler_service.stop_scheduler()

        messagebox.showinfo("Settings Reset", "All settings have been restored to defaults.")
