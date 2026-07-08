import subprocess


def check_autorun():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer').NoDriveTypeAutoRun"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        value = result.stdout.strip()

        # 255 = AutoRun disabled on all drives (recommended)
        if value == "255":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "AutoRun is disabled for all drives.",
                "recommendation": "No action required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        elif value:

            return {
                "status": "Warning",
                "risk": "Medium",
                "details": f"AutoRun policy value is {value}.",
                "recommendation": "Disable AutoRun for all drives to reduce malware risks.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine AutoRun policy.",
            "recommendation": "Verify AutoRun settings manually.",
            "detection_method": "Registry",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"AutoRun check failed: {e}",
            "recommendation": "Verify AutoRun settings manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }