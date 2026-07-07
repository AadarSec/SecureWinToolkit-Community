import subprocess


def check_smartscreen():

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\SmartScreen' "
                "-Name 'ConfigureAppInstallControlEnabled' -ErrorAction SilentlyContinue)."
                "ConfigureAppInstallControlEnabled"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout.strip()

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "SmartScreen is enabled.",
                "recommendation": "No action needed."
            }

        elif output == "0":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "SmartScreen is disabled.",
                "recommendation": "Enable SmartScreen via Windows Security > App & browser control "
                                   "to help block malicious apps and sites."
            }

        else:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "SmartScreen status could not be determined (using system default).",
                "recommendation": "Check SmartScreen settings manually via Windows Security."
            }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"SmartScreen check failed: {e}",
            "recommendation": "Verify SmartScreen settings manually via Windows Security."
        }
