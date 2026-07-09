import customtkinter as ctk


class NetworkAudit(ctk.CTkFrame):

    NETWORK_INFORMATION = [
        ("🌍", "Local IP Address"),
        ("🌐", "Public IP Address"),
        ("🚪", "Default Gateway"),
        ("📡", "DNS Servers"),
        ("📦", "DHCP Status"),
        ("🖧", "MAC Address"),
    ]

    NETWORK_CONFIGURATION = [
        ("🌐", "IPv4 Configuration"),
        ("🌍", "IPv6 Configuration"),
        ("🔌", "Network Adapter"),
        ("🛰", "Proxy Settings"),
        ("🔒", "VPN Detection"),
    ]

    NETWORK_SECURITY = [
        ("🛡", "SMB Exposure"),
        ("🛡", "WinRM Exposure"),
        ("🛡", "Remote Desktop Exposure"),
        ("🛡", "LLMNR"),
        ("🛡", "NetBIOS"),
    ]

    WIRELESS_SECURITY = [
        ("📶", "Wi-Fi SSID"),
        ("🔐", "Wi-Fi Encryption"),
        ("📡", "Signal Strength"),
    ]

    PORTS_AND_SERVICES = [
        ("🔌", "Open Ports"),
        ("⚙", "Listening Services"),
    ]

    ACTIVE_CONNECTIONS = [
        ("🔗", "Established Connections"),
        ("📡", "Listening Connections"),
        ("🌐", "ARP Cache"),
        ("🛣", "Routing Table"),
    ]

    CATEGORIES = {
        "Network Information": NETWORK_INFORMATION,
        "Network Configuration": NETWORK_CONFIGURATION,
        "Network Security": NETWORK_SECURITY,
        "Wireless Security": WIRELESS_SECURITY,
        "Ports & Services": PORTS_AND_SERVICES,
        "Active Connections": ACTIVE_CONNECTIONS,
    }

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        self.selected_category = "Network Information"
        self.checkboxes = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.build_left_panel()
        self.build_right_panel()

    # =====================================================
    # LEFT PANEL
    # =====================================================

    def build_left_panel(self):

        self.left_panel = ctk.CTkFrame(
            self,
            width=260,
            corner_radius=12,
            fg_color="#242424"
        )

        self.left_panel.grid(
            row=0,
            column=0,
            sticky="ns",
            padx=(20, 10),
            pady=20
        )

        self.left_panel.grid_propagate(False)

        ctk.CTkLabel(
            self.left_panel,
            text="🌐 Network Audit",
            font=("Segoe UI", 24, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 10)
        )

        ctk.CTkLabel(
            self.left_panel,
            text="Categories",
            font=("Segoe UI", 14, "bold"),
            text_color="#BDBDBD"
        ).pack(
            anchor="w",
            padx=20,
            pady=(10, 15)
        )

        self.category_buttons = {}

        for category in self.CATEGORIES.keys():

            count = len(self.CATEGORIES[category])

            btn = ctk.CTkButton(
                self.left_panel,
                text=f"{category} ({count})",
                anchor="w",
                width=210,
                height=40,
                fg_color="transparent",
                hover_color="#333333",
                command=lambda c=category: self.show_category(c)
            )

            btn.pack(
                fill="x",
                padx=15,
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
            corner_radius=12,
            fg_color="#2B2B2B"
        )

        self.right_panel.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(10, 20),
            pady=20
        )

        self.right_panel.grid_columnconfigure(0, weight=1)

        self.category_title = ctk.CTkLabel(
            self.right_panel,
            text="",
            font=("Segoe UI", 24, "bold")
        )

        self.category_title.pack(
            anchor="w",
            padx=20,
            pady=(20, 15)
        )

        self.scanner_frame = ctk.CTkScrollableFrame(
            self.right_panel,
            fg_color="transparent"
        )

        self.scanner_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 20)
        )

        self.show_category(self.selected_category)

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

        self.category_title.configure(text=category)

        for widget in self.scanner_frame.winfo_children():
            widget.destroy()

        self.checkboxes = {}

        select_all = ctk.CTkCheckBox(
            self.scanner_frame,
            text="Select Category",
            command=self.toggle_category
        )

        select_all.pack(
            anchor="w",
            pady=(5, 15)
        )

        self.select_all_checkbox = select_all

        for icon, scanner in self.CATEGORIES[category]:

            var = ctk.BooleanVar(value=False)

            row = ctk.CTkFrame(
                self.scanner_frame,
                fg_color="#252525",
                corner_radius=8,
                height=42
            )

            row.pack(
                fill="x",
                pady=4
            )

            row.grid_columnconfigure(1, weight=1)

            cb = ctk.CTkCheckBox(
                row,
                text="",
                variable=var,
                width=20
            )

            cb.grid(
                row=0,
                column=0,
                padx=(15, 5),
                pady=8
            )

            lbl = ctk.CTkLabel(
                row,
                text=f"{icon}  {scanner}",
                font=("Segoe UI", 13, "bold")
            )

            lbl.grid(
                row=0,
                column=1,
                sticky="w",
                padx=10
            )

            btn = ctk.CTkButton(
                row,
                text=">",
                width=34,
                height=28,
                fg_color="transparent",
                border_width=1,
                border_color="#555555",
                hover_color="#333333"
            )

            btn.grid(
                row=0,
                column=2,
                padx=12
            )

            self.checkboxes[scanner] = var

        self.build_bottom_bar()

    # =====================================================
    # CATEGORY SELECT ALL
    # =====================================================

    def toggle_category(self):

        value = self.select_all_checkbox.get()

        for var in self.checkboxes.values():
            var.set(value)

    # =====================================================
    # BOTTOM BAR
    # =====================================================

    def build_bottom_bar(self):

        bottom = ctk.CTkFrame(
            self.scanner_frame,
            fg_color="transparent"
        )

        bottom.pack(
            fill="x",
            pady=(20, 10)
        )

        self.selected_label = ctk.CTkLabel(
            bottom,
            text=f"Selected : 0 / {len(self.checkboxes)}",
            font=("Segoe UI", 12)
        )

        self.selected_label.pack(
            side="left"
        )

        self.run_button = ctk.CTkButton(
            bottom,
            text="🛡 Run Selected",
            width=180,
            height=42,
            fg_color="#8B0000",
            hover_color="#A40000",
            command=self.run_selected
        )

        self.run_button.pack(
            side="right"
        )

        for var in self.checkboxes.values():
            var.trace_add(
                "write",
                self.update_selected_count
            )

        self.update_selected_count()

    # =====================================================
    # UPDATE COUNT
    # =====================================================

    def update_selected_count(self, *args):

        selected = sum(
            1 for v in self.checkboxes.values()
            if v.get()
        )

        self.selected_label.configure(
            text=f"Selected : {selected} / {len(self.checkboxes)}"
        )

    # =====================================================
    # RUN
    # =====================================================

    def run_selected(self):

        selected = [
            scanner
            for scanner, var in self.checkboxes.items()
            if var.get()
        ]

        if not selected:
            print("No scanners selected.")
            return

        print("Selected Scanners")

        for scanner in selected:
            print(" -", scanner)