import customtkinter as ctk

from src.gui.components.details_popup import DetailsPopup
from src.core.audit_cache import AuditCache
from src.scanners.network_scanners import SCANNER_MAP

from src.core.score_engine import score_engine

from src.core.scanner_metadata import (
    MODULE,
    SCANNER_METADATA,
)


# =====================================================
# CATEGORY ICON BY SCANNER TYPE
# =====================================================
TYPE_ICONS = {
    "Security": "🛡️",
    "Configuration": "⚙️",
    "Information": "ℹ️",
}

DEFAULT_ICON = "🔹"


# =====================================================
# CATEGORY DESCRIPTIONS
# =====================================================
CATEGORY_DESCRIPTIONS = {
    "Network Information": "Collects network identity, IP addressing, and DNS information.",
    "Network Configuration": "Reviews network adapter settings, TCP/IP configuration, and connection profiles.",
    "Network Security": "Evaluates firewall rules, DNS security, and network-level protections.",
    "Wireless Information": "Displays Wi-Fi network details and signal information.",
    "Wireless Security": "Reviews Wi-Fi adapter configuration, encryption, and signal security.",
    "Network Exposure": "Inspects listening ports, running services, and exposed network endpoints.",
    "Connection Analysis": "Displays active network sessions, remote endpoints, and connection processes.",
}


# =====================================================
# BUILD NETWORK AUDIT CATEGORIES FROM SCANNER METADATA
# =====================================================
def _build_network_categories() -> dict:
    categories: dict = {}

    for scanner_name, meta in SCANNER_METADATA.items():
        if meta["module"] != MODULE["NETWORK"]:
            continue

        category = meta["category"]

        if category not in categories:
            categories[category] = {
                "description": CATEGORY_DESCRIPTIONS.get(category, ""),
                "checks": [],
            }

        icon = TYPE_ICONS.get(meta["type"], DEFAULT_ICON)
        categories[category]["checks"].append((icon, scanner_name))

    return categories


class NetworkAudit(ctk.CTkFrame):

    # =====================================================
    # CATEGORIES
    # =====================================================
    CATEGORIES = _build_network_categories()

    # =====================================================
    # CHECKS THAT REQUIRE ADMINISTRATOR PRIVILEGES
    # =====================================================
    ADMIN_REQUIRED_CHECKS = {
        "Firewall Network Policy",
        "Listening Ports",
        "Running Network Services",
        "LLMNR",
        "NetBIOS",
    }

    # =====================================================
    # INIT
    # =====================================================
    def __init__(self, parent):
        super().__init__(
            parent,
            fg_color="transparent"
        )
        self.selected_category = list(self.CATEGORIES.keys())[0] if self.CATEGORIES else "Network Information"
        self.audit_rows = {}
        self.audit_results = {}  # Persistent storage for all scan results
        self.selected_checks = []
        self.is_scanning = False
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
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
            
        if self.category_buttons:
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

        # Header
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
            text="Passed : 0",
            anchor="w"
        )
        self.warning_label = ctk.CTkLabel(
            self.score_card,
            text="Warning : 0",
            anchor="w"
        )
        self.critical_label = ctk.CTkLabel(
            self.score_card,
            text="Critical : 0",
            anchor="w"
        )
        self.remaining_label = ctk.CTkLabel(
            self.score_card,
            text="Remaining : 0",
            anchor="w"
        )
        
        self.passed_label.grid(row=4, column=0, padx=(15, 5), pady=(0, 12), sticky="nsew")
        self.warning_label.grid(row=4, column=1, padx=(5, 5), pady=(0, 12), sticky="nsew")
        self.critical_label.grid(row=4, column=2, padx=(5, 5), pady=(0, 12), sticky="nsew")
        self.remaining_label.grid(row=4, column=3, padx=(5, 15), pady=(0, 12), sticky="nsew")

        # REMOVED: self.refresh_security_score() from here
        # show_category() at the end will handle initial state properly

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
            width=50,
            anchor="e",
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
            anchor="w",
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
    # SAFE LABEL REFRESH
    # =====================================================
    def set_progress_percent(self, text):
        self.progress_percent.destroy()
        self.progress_percent = ctk.CTkLabel(
            self.progress_card,
            text=text,
            width=50,
            anchor="e",
            font=("Segoe UI", 15, "bold"),
            text_color="#4EA3FF"
        )
        self.progress_percent.grid(
            row=0,
            column=1,
            sticky="e",
            padx=15
        )
        self.update()

    def set_current_scanner(self, text):
        self.current_scanner.destroy()
        self.current_scanner = ctk.CTkLabel(
            self.progress_card,
            text=text,
            anchor="w",
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
        self.update()

    # =====================================================
    # REFRESH SECURITY SCORE (FIXED - EMPTY CHECK ADDED)
    # =====================================================
    def refresh_security_score(self):
        """
        Refresh score card using the score engine.
        If no scans done yet, force 0/100 and 'Not Scanned'.
        """
        # FIX: Agar koi scan na hua ho toh score engine call mat karo
        if not self.audit_results:
            total_scanners = sum(
                len(cat["checks"]) for cat in self.CATEGORIES.values()
            )
            
            self.score_label.configure(text="0 / 100")
            self.score_progress.set(0)
            self.score_status.configure(
                text="Not Scanned",
                text_color="#9CA3AF"
            )
            self.passed_label.configure(text="Passed : 0")
            self.warning_label.configure(text="Warning : 0")
            self.critical_label.configure(text="Critical : 0")
            self.remaining_label.configure(text=f"Remaining : {total_scanners}")
            
            self.score_card.update()
            self.update_idletasks()
            return

        # Jab scans ho chuke hon tab score engine use karo
        summary = score_engine.refresh(self.audit_results)
        stats = score_engine.get_statistics()

        self.score_label.configure(
            text=f"{summary['windows_score']:.1f} / 100"
        )

        self.score_progress.set(
            summary["windows_score"] / 100
        )

        self.score_status.configure(
            text=summary["security_posture"],
            text_color=summary["posture_color"]
        )

        self.passed_label.configure(
            text=f"Passed : {stats['passed']}"
        )

        self.warning_label.configure(
            text=f"Warning : {stats['warning']}"
        )

        self.critical_label.configure(
            text=f"Critical : {stats['critical']}"
        )

        self.remaining_label.configure(
            text=f"Remaining : {stats['not_scanned']}"
        )
        
        self.score_card.update()
        self.update_idletasks()

    # =====================================================
    # SHOW CATEGORY
    # =====================================================
    def show_category(self, category):
        if self.is_scanning:
            return
            
        self.selected_category = category
        
        for btn in self.category_buttons.values():
            btn.configure(fg_color="transparent")
        self.category_buttons[category].configure(
            fg_color="#8B0000"
        )
        
        self.category_title.configure(text=category)
        self.category_description.configure(
            text=self.CATEGORIES[category]["description"]
        )
        
        for widget in self.content_frame.winfo_children():
            if widget not in (self.score_card, self.progress_card):
                widget.destroy()

        # FIX: Reset the audit progress card whenever the user switches
        # categories, so a finished scan's progress from the previous
        # category doesn't carry over and show up in the new one.
        self.progress_bar.set(0)
        self.set_progress_percent("0%")
        self.set_current_scanner("Current Scanner : Waiting...")

        self.audit_rows = {}
        self.select_all_var = ctk.BooleanVar(value=False)
        
        select_frame = ctk.CTkFrame(
            self.content_frame,
            fg_color="transparent"
        )
        select_frame.pack(fill="x", pady=(0, 10))
        
        select_all = ctk.CTkCheckBox(
            select_frame,
            text="Select Category",
            variable=self.select_all_var,
            command=self.toggle_category
        )
        select_all.pack(side="left")
        
        self.selected_label = ctk.CTkLabel(
            select_frame,
            text="Selected : 0 / 0",
            font=("Segoe UI", 12)
        )
        self.selected_label.pack(side="right")
        
        self.scanner_frame = ctk.CTkScrollableFrame(
            self.content_frame,
            fg_color="transparent"
        )
        self.scanner_frame.pack(fill="both", expand=True)
        
        for icon, scanner in self.CATEGORIES[category]["checks"]:
            self.create_scanner_row(icon, scanner)
            if scanner in self.audit_results:
                self.update_row_badge(scanner, self.audit_results[scanner])

        self.build_bottom_bar()
        self.refresh_security_score()
        self.right_panel.update()
        self.update_idletasks()

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
        row.pack(fill="x", pady=4)
        row.grid_columnconfigure(1, weight=1)
        
        check_var = ctk.BooleanVar(value=False)
        checkbox = ctk.CTkCheckBox(
            row,
            text="",
            variable=check_var,
            width=20
        )
        checkbox.grid(row=0, column=0, padx=(16, 6), pady=10)
        
        title = ctk.CTkLabel(
            row,
            text=f"{icon}  {scanner}",
            font=("Segoe UI", 13, "bold"),
            anchor="w"
        )
        title.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        
        badge = ctk.CTkLabel(
            row,
            text="⚫ Not Scanned",
            width=130,
            height=28,
            fg_color="#404040",
            corner_radius=12,
            font=("Segoe UI", 11)
        )
        badge.grid(row=0, column=2, padx=10)
        
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
        details.grid(row=0, column=3, padx=12)
        
        self.audit_rows[scanner] = {
            "check_var": check_var,
            "badge": badge,
            "button": details
        }

    # =====================================================
    # UPDATE ROW BADGE
    # =====================================================
    def update_row_badge(self, scanner, result):
        if scanner not in self.audit_rows:
            return
            
        badge = self.audit_rows[scanner]["badge"]
        status = result["status"]
        if status == "Passed":
            badge.configure(text="🟢 Passed", fg_color="#16A34A")
        elif status == "Warning":
            badge.configure(text="🟡 Warning", fg_color="#D97706")
        else:
            badge.configure(text="🔴 Critical", fg_color="#DC2626")

    # =====================================================
    # BOTTOM BAR
    # =====================================================
    def build_bottom_bar(self):
        for row in self.audit_rows.values():
            row["check_var"].trace_add("write", self.update_selected_count)
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
            1 for row in self.audit_rows.values() if row["check_var"].get()
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
        if self.is_scanning:
            return

        selected = self.get_selected_checks()
        if not selected:
            return

        self.is_scanning = True
        self.run_button.configure(
            text="Running...",
            state="disabled"
        )

        admin_needed = [
            name for name in selected
            if name in self.ADMIN_REQUIRED_CHECKS
        ]

        if admin_needed:
            from src.gui.components.admin_warning_popup import AdminWarningPopup
            from src.scanners.admin_utils import is_admin
            
            if not is_admin():
                AdminWarningPopup(
                    self.winfo_toplevel(),
                    admin_needed,
                    on_continue=lambda: self._start_audit(selected),
                    on_cancel=self._reset_run_button
                )
                return

        self._start_audit(selected)

    # =====================================================
    # RESET RUN BUTTON
    # =====================================================
    def _reset_run_button(self):
        self.is_scanning = False
        self.run_button.configure(
            text="🛡 Run Selected",
            state="normal"
        )

    # =====================================================
    # START AUDIT
    # =====================================================
    def _start_audit(self, selected):
        self.is_scanning = True
        self.run_button.configure(
            text="Running...",
            state="disabled"
        )
        self.progress_bar.set(0)
        self.set_progress_percent("0%")
        self.set_current_scanner("Preparing audit...")
        
        total = len(selected)
        
        for current, scanner in enumerate(selected, start=1):
            scan_function = SCANNER_MAP.get(scanner)
            if scan_function is None:
                result = {
                    "status": "Warning",
                    "risk": "Unknown",
                    "details": f"No scanner is registered for '{scanner}'.",
                    "recommendation": "Verify this check manually.",
                    "detection_method": "None",
                    "confidence": "0%"
                }
            else:
                try:
                    result = scan_function()
                except Exception as e:
                    result = {
                        "status": "Warning",
                        "risk": "Unknown",
                        "details": f"'{scanner}' scan failed unexpectedly:\n\n{e}",
                        "recommendation": "Verify this check manually.",
                        "detection_method": "Python Exception",
                        "confidence": "0%"
                    }
            
            self.audit_results[scanner] = result
            self.audit_progress(current, total, scanner, result)
            
        self.finish_scan()

    # =====================================================
    # LIVE PROGRESS
    # =====================================================
    def audit_progress(self, current, total, scanner, result):
        percent = int((current / total) * 100)
        percent = max(0, min(percent, 100))

        self.progress_bar.set(percent / 100)
        self.set_progress_percent(f"{percent}%")
        self.set_current_scanner(f"Scanning : {scanner}")

        if scanner in self.audit_rows:
            badge = self.audit_rows[scanner]["badge"]
            status = result["status"]
            if status == "Passed":
                badge.configure(text="🟢 Passed", fg_color="#16A34A")
            elif status == "Warning":
                badge.configure(text="🟡 Warning", fg_color="#D97706")
            else:
                badge.configure(text="🔴 Critical", fg_color="#DC2626")
        
        self.update_idletasks()

    # =====================================================
    # FINISH AUDIT
    # =====================================================
    def finish_scan(self):
        self.refresh_security_score()

        self.progress_bar.set(1)
        self.set_progress_percent("100%")
        self.set_current_scanner("Audit Completed")

        self.run_button.configure(
            text="🛡 Run Selected",
            state="normal"
        )
        self.is_scanning = False

        AuditCache.set_results(self.audit_results)
        self.update_idletasks()