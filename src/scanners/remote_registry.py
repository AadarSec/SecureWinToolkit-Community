import subprocess


def check_remote_registry():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Service RemoteRegistry).Status"
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
                "details": "Remote Registry service is currently running.",
                "recommendation": "Disable the Remote Registry service unless it is required for administration.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        elif status == "stopped":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Remote Registry service is disabled or stopped.",
                "recommendation": "No action required.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        else:

            return {
                "status": "Warning",
                "risk": "Unknown",
                "details": f"Unexpected service status: {status}",
                "recommendation": "Verify the Remote Registry service manually.",
                "detection_method": "Windows Service",
                "confidence": "80%"
            }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Remote Registry check failed: {e}",
            "recommendation": "Verify the Remote Registry service manually.",
            "detection_method": "Windows Service",
            "confidence": "0%"
        }