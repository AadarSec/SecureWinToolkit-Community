from .powershell_utils import run_ps


def check_guest_account():

    try:

        result = run_ps("(Get-LocalUser -Name 'Guest').Enabled")

        enabled = result.stdout.lower()

        if enabled == "false":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "The built-in Guest account is disabled.",
                "recommendation": "No action required.",
                "detection_method": "PowerShell LocalUser",
                "confidence": "100%"
            }

        elif enabled == "true":

            return {
                "status": "Critical",
                "risk": "High",
                "details": "The built-in Guest account is enabled.",
                "recommendation": "Disable the Guest account to reduce unauthorized access risk.",
                "detection_method": "PowerShell LocalUser",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Guest account status.",
            "recommendation": "Verify the Guest account manually.",
            "detection_method": "PowerShell LocalUser",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Guest account check failed: {e}",
            "recommendation": "Verify the Guest account manually.",
            "detection_method": "PowerShell LocalUser",
            "confidence": "0%"
        }