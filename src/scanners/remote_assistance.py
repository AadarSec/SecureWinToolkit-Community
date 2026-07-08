import subprocess


def check_remote_assistance():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance').fAllowToGetHelp"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        value = result.stdout.strip()

        if value == "0":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Remote Assistance is disabled.",
                "recommendation": "No action required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        elif value == "1":

            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Remote Assistance is enabled.",
                "recommendation": "Disable Remote Assistance if it is not required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Remote Assistance status.",
            "recommendation": "Verify Remote Assistance manually.",
            "detection_method": "Registry",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Remote Assistance check failed: {e}",
            "recommendation": "Verify Remote Assistance manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }