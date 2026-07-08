import subprocess


def check_administrator_account():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-LocalUser -Name 'Administrator').Enabled"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        enabled = result.stdout.strip().lower()

        if enabled == "false":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "The built-in Administrator account is disabled.",
                "recommendation": "No action required.",
                "detection_method": "PowerShell LocalUser",
                "confidence": "100%"
            }

        elif enabled == "true":

            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "The built-in Administrator account is enabled.",
                "recommendation": "Disable or rename the built-in Administrator account if it is not required.",
                "detection_method": "PowerShell LocalUser",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine the Administrator account status.",
            "recommendation": "Verify the Administrator account manually.",
            "detection_method": "PowerShell LocalUser",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Administrator account check failed: {e}",
            "recommendation": "Verify the Administrator account manually.",
            "detection_method": "PowerShell LocalUser",
            "confidence": "0%"
        }