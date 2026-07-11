import subprocess
import webbrowser
import customtkinter as ctk


# ---------------------------------------------------------------------------
# Local threat-intelligence knowledge base.
#
# Har scanner apne result dict mein ye keys bhej sakta hai:
#   why_important, exposure, attacks (list), risk_level, mitre,
#   recommendation, best_practice, references (list)
#
# Agar scanner ye keys nahi bhejta, to popup neeche diye gaye
# THREAT_INTEL dict se (scanner title ke basis par) auto-fill kar dega,
# taake purane scanners ko chhue bina bhi rich detail mil jaye.
# ---------------------------------------------------------------------------
THREAT_INTEL = {

    "Windows Defender": {
        "why_important": (
            "Microsoft Defender provides real-time malware detection and "
            "prevents malicious software from executing on the endpoint."
        ),
        "exposure": (
            "If disabled, malware can execute without detection, increasing "
            "the risk of ransomware, trojans and spyware."
        ),
        "attacks": ["Ransomware", "Trojan", "Malware", "Cryptomining"],
        "risk_level": "High",
        "recommendation": (
            "Enable Microsoft Defender Real-time Protection. Keep signatures "
            "updated. Perform scheduled scans."
        ),
        "best_practice": (
            "Microsoft recommends keeping real-time protection, cloud-delivered "
            "protection and automatic sample submission enabled at all times."
        ),
        "mitre": "T1562.001 - Impair Defenses: Disable or Modify Tools",
    },

    "SMBv1 Enabled": {
        "why_important": "SMBv1 is deprecated and contains multiple security vulnerabilities.",
        "exposure": (
            "Remote code execution, lateral movement and network worm propagation."
        ),
        "attacks": ["WannaCry", "NotPetya", "EternalBlue", "SMB Relay"],
        "risk_level": "Critical",
        "recommendation": (
            "Disable SMBv1 immediately. Use SMBv2 or SMBv3. Reboot after disabling."
        ),
        "best_practice": (
            "Microsoft has disabled SMBv1 by default since Windows 10 1709 / "
            "Windows Server 2019 and recommends it stay disabled."
        ),
        "mitre": "T1210 - Exploitation of Remote Services",
    },

    "BitLocker Disabled": {
        "why_important": "BitLocker encrypts data at rest.",
        "exposure": "Anyone with physical access can read the drive.",
        "attacks": ["Offline credential extraction", "Disk theft", "Data theft", "Cold boot attacks"],
        "risk_level": "High",
        "recommendation": (
            "Enable BitLocker on all fixed drives. Store the recovery key securely."
        ),
        "best_practice": (
            "Microsoft recommends BitLocker with TPM + PIN and escrow of the "
            "recovery key in Azure AD / Active Directory."
        ),
        "mitre": "T1200 - Hardware Additions / Physical Access based data theft",
    },

    "Secure Boot Disabled": {
        "why_important": (
            "Secure Boot ensures only trusted, signed code runs during the boot process."
        ),
        "exposure": "Allows unsigned or malicious bootloaders to load before the OS.",
        "attacks": ["Bootkits", "Rootkits", "UEFI Malware", "Bootloader replacement"],
        "risk_level": "Critical",
        "recommendation": "Enable Secure Boot in UEFI/BIOS settings.",
        "best_practice": (
            "Microsoft requires Secure Boot for Windows 11 and recommends it be "
            "enabled on all Windows 10 devices that support UEFI."
        ),
        "mitre": "T1542.003 - Pre-OS Boot: Bootkit",
    },

    "Windows Update": {
        "why_important": (
            "Security updates patch known vulnerabilities before attackers can exploit them."
        ),
        "exposure": "Unpatched systems remain vulnerable to publicly known exploits.",
        "attacks": ["Known CVEs", "Privilege Escalation", "Remote Code Execution", "Zero-day exploitation"],
        "risk_level": "High",
        "recommendation": "Install all pending updates and enable automatic updates.",
        "best_practice": (
            "Microsoft recommends keeping automatic updates enabled and applying "
            "security patches within the standard 30-day patching window."
        ),
        "mitre": "T1190 - Exploit Public-Facing Application",
    },

    "Firewall": {
        "why_important": "The firewall controls inbound/outbound network traffic to the device.",
        "exposure": "A disabled firewall exposes open ports and services directly to attackers.",
        "attacks": ["Port scanning", "Remote exploitation", "Lateral movement", "Unauthorized access"],
        "risk_level": "High",
        "recommendation": "Enable Windows Firewall on all network profiles (Domain, Private, Public).",
        "best_practice": (
            "Microsoft recommends keeping Windows Defender Firewall enabled on "
            "all profiles with default-deny inbound rules."
        ),
        "mitre": "T1046 - Network Service Discovery",
    },

    "Password Policy": {
        "why_important": "A strong password policy is the first line of defense against account compromise.",
        "exposure": "Weak passwords make accounts easy to guess or crack.",
        "attacks": ["Password spraying", "Credential stuffing", "Brute force", "Dictionary attacks"],
        "risk_level": "Medium",
        "recommendation": (
            "Enforce minimum length, complexity, account lockout threshold and "
            "regular password expiry."
        ),
        "best_practice": (
            "Microsoft's modern guidance favors long passphrases (14+ characters), "
            "MFA, and banning commonly breached passwords over frequent forced resets."
        ),
        "mitre": "T1110 - Brute Force",
    },
}


SEVERITY_COLORS = {
    "critical": "#FF5555",
    "high": "#FF8C42",
    "medium": "#FFC107",
    "low": "#4CAF50",
    "warning": "#FFC107",
    "passed": "#4CAF50",
    "pass": "#4CAF50",
    "ok": "#4CAF50",
}


class DetailsPopup(ctk.CTkToplevel):

    def __init__(self, parent, title, result):

        super().__init__(parent)

        self.title(title)

        self.geometry("760x700")

        self.resizable(False, False)

        self.grab_set()

        self.update_idletasks()

        x = (self.winfo_screenwidth() // 2) - (760 // 2)
        y = (self.winfo_screenheight() // 2) - (700 // 2)

        self.geometry(f"760x700+{x}+{y}")

        self.configure(fg_color="#1F1F1F")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Merge built-in threat intel with whatever the scanner itself
        # provided. Values explicitly returned by the scanner always win.
        intel = dict(THREAT_INTEL.get(title, {}))
        intel.update({k: v for k, v in result.items() if v not in (None, "", [])})
        data = intel

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

                font=("Segoe UI", 18, "bold"),

                text_color="#4EA8FF"

            ).pack(anchor="w", pady=(15, 5))

        def value(text, color=None):

            ctk.CTkLabel(

                frame,

                text=text,

                justify="left",

                wraplength=680,

                font=("Segoe UI", 13),

                text_color=color if color else "#E0E0E0"

            ).pack(anchor="w")

        def bullet_list(items):

            for item in items:
                value("•  " + str(item))

        def severity_color(text):
            return SEVERITY_COLORS.get(str(text).strip().lower())

        def link(url):

            label = ctk.CTkLabel(

                frame,

                text=url,

                justify="left",

                wraplength=680,

                font=("Segoe UI", 13, "underline"),

                text_color="#4EA8FF",

                cursor="hand2"

            )

            label.pack(anchor="w")

            label.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

        # ---------------- Status & Risk -----------------

        heading("Status")
        status_text = data.get("status", "N/A")
        value(status_text, severity_color(status_text))

        heading("Risk Level")
        risk_text = data.get("risk_level", data.get("risk", "N/A"))
        value(risk_text, severity_color(risk_text))

        if "confidence" in data:
            heading("Confidence")
            value(data["confidence"])

        if "detection_method" in data:
            heading("Detection Method")
            value(data["detection_method"])

        # ---------------- Threat Intelligence -----------------

        if data.get("why_important"):
            heading("Why Is This Important?")
            value(data["why_important"])

        if data.get("exposure"):
            heading("Security Exposure")
            value(data["exposure"])

        if data.get("attacks"):
            heading("Possible Attacks")
            bullet_list(data["attacks"])

        if data.get("mitre"):
            heading("MITRE ATT&CK Mapping")
            value(data["mitre"])

        # ---------------- Raw Scan Details -----------------

        if data.get("details"):
            heading("Details")
            value(data["details"])

        if data.get("updates"):
            heading("Pending Updates")
            bullet_list(data["updates"])

        # ---------------- Guidance -----------------

        if data.get("recommendation"):
            heading("Recommendation")
            value(data["recommendation"])

        if data.get("best_practice"):
            heading("Microsoft Best Practice")
            value(data["best_practice"])

        if data.get("references"):
            heading("Reference Links")
            for ref in data["references"]:
                link(ref)

        # ---------------- Buttons -----------------

        button_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        button_frame.grid(
            row=1,
            column=0,
            pady=(0, 15)
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
