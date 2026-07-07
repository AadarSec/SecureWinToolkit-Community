import subprocess


def check_windows_defender():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-MpComputerStatus).RealTimeProtectionEnabled"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout.strip().lower()

        if output == "true":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Microsoft Defender Real-Time Protection is enabled and actively protecting this system.",
                "recommendation": "No action required."
            }

        elif output == "false":

            return {
                "status": "Critical",
                "risk": "High",
                "details": "Microsoft Defender Real-Time Protection is disabled.",
                "recommendation": "Enable Microsoft Defender Real-Time Protection immediately."
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Microsoft Defender status.",
            "recommendation": "Verify Microsoft Defender settings manually."
        }

    except Exception:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Windows Defender check failed.",
            "recommendation": "Run the audit again or verify Windows Defender manually."
        }