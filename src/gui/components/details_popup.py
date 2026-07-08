import subprocess
import customtkinter as ctk


class DetailsPopup(ctk.CTkToplevel):

    def __init__(self, parent, title, result):

        super().__init__(parent)

        self.title(title)

        self.geometry("700x650")

        self.resizable(False, False)

        self.grab_set()

        self.update_idletasks()

        width = self.winfo_width()
        height = self.winfo_height()

        x = (self.winfo_screenwidth() // 2) - (700 // 2)
        y = (self.winfo_screenheight() // 2) - (650 // 2)

        self.geometry(f"700x650+{x}+{y}")

        self.configure(fg_color="#1F1F1F")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        frame = ctk.CTkScrollableFrame(
            self,
            fg_color="#262626"
        )

        frame.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=15,
            pady=15
        )

        def heading(text):

            ctk.CTkLabel(

                frame,

                text=text,

                font=("Segoe UI",18,"bold"),

                text_color="#4EA8FF"

            ).pack(anchor="w", pady=(15,5))

        def value(text):

            ctk.CTkLabel(

                frame,

                text=text,

                justify="left",

                wraplength=620,

                font=("Segoe UI",13)

            ).pack(anchor="w")

        heading("Status")

        value(result.get("status","N/A"))

        heading("Risk")

        value(result.get("risk","N/A"))

        if "confidence" in result:

            heading("Confidence")

            value(result["confidence"])

        if "detection_method" in result:

            heading("Detection Method")

            value(result["detection_method"])

        heading("Details")

        value(result.get("details",""))

        if "updates" in result and result["updates"]:

            heading("Pending Updates")

            for update in result["updates"]:

                value("• " + update)

        heading("Recommendation")

        value(result.get("recommendation",""))

        button_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        button_frame.grid(
            row=1,
            column=0,
            pady=(0,15)
        )

        if title == "Windows Update":

            ctk.CTkButton(

                button_frame,

                text="Open Windows Update Settings",

                width=240,

                fg_color="#8B0000",

                hover_color="#A40000",

                command=self._open_windows_update_settings

            ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(

            button_frame,

            text="Close",

            width=120,

            command=self.destroy

        ).pack(side="left")

    def _open_windows_update_settings(self):

        try:
            subprocess.Popen(
                [
                    "cmd",
                    "/c",
                    "start",
                    "ms-settings:windowsupdate"
                ],
                shell=True
            )

        except Exception:
            pass