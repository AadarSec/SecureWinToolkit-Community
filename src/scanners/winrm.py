import subprocess


def check_winrm():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Service WinRM).Status"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        status = result.stdout.strip().lower()

        if status == "running":

            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Windows Remote Management (WinRM) service is running.",
                "recommendation": "Disable WinRM if remote management is not required.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        elif status == "stopped":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Windows Remote Management (WinRM) service is stopped.",
                "recommendation": "No action required.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        else:

            return {
                "status": "Warning",
                "risk": "Unknown",
                "details": f"Unexpected WinRM service state: {status}",
                "recommendation": "Verify WinRM configuration manually.",
                "detection_method": "Windows Service",
                "confidence": "80%"
            }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"WinRM check failed: {e}",
            "recommendation": "Verify WinRM manually.",
            "detection_method": "Windows Service",
            "confidence": "0%"
        }