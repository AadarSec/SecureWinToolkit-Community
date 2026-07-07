import customtkinter as ctk


class InfoCard(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        title,
        value,
        icon="",
        status=None,
        show_progress=False,
        detail=None,
        force_clickable=False
    ):
        super().__init__(
            parent,
            fg_color="#2B2B2B",
            corner_radius=12,
            border_width=1
        )

        self.status_colors = {
            "healthy": "#22C55E",
            "warning": "#F59E0B",
            "critical": "#EF4444",
            "normal": "#555555"
        }

        self._status = status
        self._detail = detail
        self._force_clickable = force_clickable
        self._display_title = f"{icon} {title}".strip()

        border_color = (
            "#555555"
            if status is None
            else self.status_colors.get(status, "#555555")
        )

        self.configure(border_color=border_color)

        # ---------------- Header ----------------

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(8, 2))

        self.title_label = ctk.CTkLabel(
            header,
            text=self._display_title,
            font=("Segoe UI", 11, "bold"),
            text_color="#CFCFCF"
        )
        self.title_label.pack(anchor="w")

        # ---------------- Value ----------------

        main_value, sub_value = self._split_value(value)

        self.value_label = ctk.CTkLabel(
            self,
            text=main_value,
            font=("Segoe UI", 16, "bold"),
            text_color="white",
            justify="left",
            anchor="w",
            wraplength=220
        )
        self.value_label.pack(
            anchor="w",
            padx=10,
            pady=(2, 1 if sub_value else 6)
        )

        self.subtitle_label = None

        if sub_value:
            self.subtitle_label = ctk.CTkLabel(
                self,
                text=sub_value,
                font=("Segoe UI", 10),
                text_color="#9CA3AF",
                justify="left",
                anchor="w",
                wraplength=220
            )
            self.subtitle_label.pack(
                anchor="w",
                padx=10,
                pady=(0, 6)
            )

        # ---------------- Status ----------------

        self.status_label = None

        if status is not None:
            self.status_label = ctk.CTkLabel(
                self,
                text=self._status_line_text(),
                font=("Segoe UI", 11),
                text_color=border_color
            )
            self.status_label.pack(
                anchor="w",
                padx=10,
                pady=(0, 3)
            )

        # ---------------- Progress ----------------

        self.progress = None

        if show_progress:
            self.progress = ctk.CTkProgressBar(self, height=8)
            self.progress.pack(
                fill="x",
                padx=10,
                pady=(0, 8)
            )
            self.progress.set(0)

        self._bind_click_events()
        self._refresh_interactivity()

    @staticmethod
    def _truncate(text, max_len):
        text = str(text)
        if len(text) <= max_len:
            return text
        return text[: max_len - 1].rstrip() + "…"

    @classmethod
    def _split_value(cls, value):
        parts = str(value).split("\n", 1)
        main = cls._truncate(parts[0], 28)
        sub = cls._truncate(parts[1], 42) if len(parts) > 1 else None
        return main, sub

    def _status_line_text(self):
        base = self._status.capitalize() if self._status else ""

        if self._is_interactive():
            return f"{base}  ·  Click for details" if base else "Click for details"

        return base

    def _clickable_widgets(self):
        widgets = [
            self,
            self.title_label,
            self.value_label
        ]

        if self.subtitle_label:
            widgets.append(self.subtitle_label)

        if self.status_label:
            widgets.append(self.status_label)

        return widgets

    def _bind_click_events(self):
        for widget in self._clickable_widgets():
            widget.bind("<Button-1>", self._on_click)

    def _is_interactive(self):
        if self._force_clickable and bool(self._detail):
            return True

        return (
            self._status in ("warning", "critical")
            and bool(self._detail)
        )

    def _refresh_interactivity(self):
        cursor = "hand2" if self._is_interactive() else ""

        try:
            self.configure(cursor=cursor)

            for widget in self._clickable_widgets():
                widget.configure(cursor=cursor)

        except Exception:
            pass

        if self.status_label:
            self.status_label.configure(
                text=self._status_line_text()
            )

    def _on_click(self, event=None):
        if self._is_interactive():
            self._show_detail_popup()

    def _show_detail_popup(self):
        color = self.status_colors.get(
            self._status,
            "#555555"
        )

        icon = {"warning": "⚠", "critical": "🛑", "healthy": "✅"}.get(
            self._status, "ℹ"
        )

        popup = ctk.CTkToplevel(self)
        popup.title(self._display_title)
        popup.geometry("400x220")
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

        header = ctk.CTkLabel(
            popup,
            text=f"{icon} {self._display_title}",
            font=("Segoe UI", 15, "bold"),
            text_color=color
        )
        header.pack(anchor="w", padx=18, pady=(18, 8))

        body = ctk.CTkLabel(
            popup,
            text=self._detail,
            wraplength=350,
            justify="left"
        )
        body.pack(anchor="w", padx=18)

        ctk.CTkButton(
            popup,
            text="Close",
            command=popup.destroy
        ).pack(pady=18)

    def update_value(self, value):
        main, sub = self._split_value(value)

        self.value_label.configure(text=main)

        if self.subtitle_label:
            self.subtitle_label.configure(
                text=sub if sub else ""
            )

    def update_status(self, status):
        self._status = status

        if self.status_label:
            color = self.status_colors.get(status, "#555555")

            self.configure(border_color=color)

            self.status_label.configure(
                text=self._status_line_text(),
                text_color=color
            )

        self._refresh_interactivity()

    def update_detail(self, detail):
        self._detail = detail
        self._refresh_interactivity()

    def set_progress(self, value):
        if self.progress:
            self.progress.set(value / 100)