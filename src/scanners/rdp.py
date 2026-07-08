import subprocess


def check_rdp():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
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
                "details": "Remote Desktop is disabled.",
                "recommendation": "No action required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        elif output == "0":

            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Remote Desktop is enabled.",
                "recommendation": "Disable Remote Desktop unless remote access is required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Remote Desktop status.",
            "recommendation": "Verify Remote Desktop settings manually.",
            "detection_method": "Registry",
            "confidence": "50%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Remote Desktop check failed: {e}",
            "recommendation": "Verify Remote Desktop settings manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }