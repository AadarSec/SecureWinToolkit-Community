import subprocess


def check_uac():

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty -Path "
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                "-Name 'EnableLUA').EnableLUA"
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
                "details": "User Account Control (UAC) is enabled.",
                "recommendation": "No action needed."
            }

        elif output == "0":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "User Account Control (UAC) is disabled.",
                "recommendation": "Enable UAC via Control Panel > User Accounts > Change UAC settings "
                                   "to prevent unauthorized system changes."
            }

        else:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "UAC status could not be determined.",
                "recommendation": "Check UAC settings manually via Control Panel."
            }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"UAC check failed: {e}",
            "recommendation": "Verify UAC settings manually via Control Panel."
        }
