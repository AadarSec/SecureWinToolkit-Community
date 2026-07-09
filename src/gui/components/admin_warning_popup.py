import os
import sys
import ctypes

import customtkinter as ctk


class AdminWarningPopup(ctk.CTkToplevel):
    """
    Themed dialog shown BEFORE an audit runs when one or more of the
    SELECTED checks require Administrator privileges to return
    accurate results, and the app is not currently elevated.

    Matches the app's existing dark theme (#242424 / #2B2B2B
    backgrounds, #8B0000 accent, Segoe UI typography).

    - "Run as Administrator" relaunches the app elevated (via the
      native Windows UAC prompt) and closes the current instance.
    - "Not Now" dismisses the popup and lets the audit proceed
      anyway (the affected checks will simply report degraded/
      unknown results).
    """

    def __init__(self, parent, checks, on_continue=None, on_cancel=None):
        super().__init__(parent)

        self._on_continue = on_continue
        self._on_cancel = on_cancel
        self._resolved = False

        self.title("Administrator Privileges Required")
        self.resizable(False, False)
        self.configure(fg_color="#2B2B2B")

        # Keep the popup on top of and tied to the main window
        self.transient(parent)
        self.after(50, self.grab_set)
        self.protocol("WM_DELETE_WINDOW", self._handle_cancel)

        self.grid_columnconfigure(0, weight=1)

        # =====================================================
        # ICON
        # =====================================================
        icon_label = ctk.CTkLabel(
            self,
            text="⚠",
            font=("Segoe UI", 42),
            text_color="#D97706"
        )
        icon_label.pack(pady=(28, 6))

        # =====================================================
        # TITLE
        # =====================================================
        title_label = ctk.CTkLabel(
            self,
            text="Administrator Privileges Required",
            font=("Segoe UI", 17, "bold"),
            text_color="#FFFFFF"
        )
        title_label.pack(pady=(0, 12))

        # =====================================================
        # MESSAGE CARD
        # =====================================================
        card = ctk.CTkFrame(
            self,
            corner_radius=12,
            fg_color="#242424"
        )
        card.pack(
            fill="x",
            padx=20,
            pady=(0, 15)
        )

        checks_text = "\n".join(f"•  {c}" for c in checks)

        ctk.CTkLabel(
            card,
            text=checks_text,
            font=("Segoe UI", 12, "bold"),
            text_color="#EF4444",
            justify="left",
            anchor="w"
        ).pack(
            fill="x",
            padx=15,
            pady=(12, 12)
        )

        message_label = ctk.CTkLabel(
            self,
            text=(
                "The selected checks above need Administrator privileges to "
                "return accurate results, and the app isn't currently "
                "elevated.\n\n"
                "Relaunch as Administrator now, or continue anyway and "
                "these checks may show incomplete results."
            ),
            font=("Segoe UI", 12),
            text_color="#9CA3AF",
            wraplength=380,
            justify="left"
        )
        message_label.pack(
            padx=20,
            pady=(0, 15)
        )

        # =====================================================
        # ERROR LABEL (hidden unless elevation fails/cancelled)
        # =====================================================
        self.error_label = ctk.CTkLabel(
            self,
            text="",
            font=("Segoe UI", 11),
            text_color="#EF4444",
            wraplength=380,
            justify="left"
        )
        self.error_label.pack(
            padx=20,
            pady=(0, 5)
        )

        # =====================================================
        # BUTTONS
        # =====================================================
        button_row = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        button_row.pack(pady=(10, 25))

        not_now_button = ctk.CTkButton(
            button_row,
            text="Not Now",
            width=120,
            height=38,
            fg_color="transparent",
            hover_color="#333333",
            border_width=1,
            border_color="#555555",
            corner_radius=8,
            font=("Segoe UI", 13),
            command=self._handle_not_now
        )
        not_now_button.grid(
            row=0,
            column=0,
            padx=(0, 10)
        )

        run_as_admin_button = ctk.CTkButton(
            button_row,
            text="🛡 Run as Administrator",
            width=210,
            height=38,
            fg_color="#8B0000",
            hover_color="#A40000",
            corner_radius=8,
            font=("Segoe UI", 13, "bold"),
            command=self._relaunch_as_admin
        )
        run_as_admin_button.grid(
            row=0,
            column=1
        )

        # Size the window to fit its actual content, then center it.
        # A fixed guessed geometry was clipping the buttons off the
        # bottom of the dialog on some systems/DPI settings.
        self.after(10, self._fit_and_center)

    # =====================================================
    # NOT NOW -> close popup and let the audit proceed anyway
    # =====================================================
    def _handle_not_now(self):

        if self._resolved:
            return
        self._resolved = True

        if self._on_continue:
            self._on_continue()

        self.destroy()

    # =====================================================
    # CANCEL (closed via the X button) -> don't run the audit
    # =====================================================
    def _handle_cancel(self):

        if self._resolved:
            return
        self._resolved = True

        if self._on_cancel:
            self._on_cancel()

        self.destroy()

    # =====================================================
    # RELAUNCH AS ADMINISTRATOR
    # =====================================================
    def _relaunch_as_admin(self):

        try:
            if getattr(sys, "frozen", False):
                # Running as a packaged executable (e.g. PyInstaller)
                executable = sys.executable
                params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
            else:
                # Running as a Python script: relaunch the same
                # interpreter with the same script/arguments.
                executable = sys.executable
                params = " ".join(f'"{arg}"' for arg in sys.argv)

            # ShellExecuteW with the "runas" verb triggers the native
            # Windows UAC elevation prompt.
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                executable,
                params,
                None,
                1
            )

            # Return codes > 32 indicate success; anything else means
            # the elevation failed or the user cancelled the UAC prompt.
            if result > 32:
                self._resolved = True  # don't also run the un-elevated audit
                self.destroy()
                # Close the current, non-elevated instance so the user
                # isn't left running two copies of the app.
                os._exit(0)
            else:
                self.error_label.configure(
                    text="Elevation was cancelled or failed. The app is still running "
                         "without Administrator privileges."
                )

        except Exception as e:
            self.error_label.configure(
                text=f"Could not relaunch as Administrator: {e}"
            )

    # =====================================================
    # SIZE TO CONTENT + CENTER ON PARENT
    # =====================================================
    def _fit_and_center(self):

        self.update_idletasks()

        parent = self.master

        w = self.winfo_reqwidth()
        h = self.winfo_reqheight()

        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()

        x = px + (pw - w) // 2
        y = py + (ph - h) // 2

        self.geometry(f"{w}x{h}+{x}+{y}")
