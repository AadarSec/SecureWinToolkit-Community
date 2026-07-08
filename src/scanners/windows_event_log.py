import json
import subprocess


def check_windows_event_log():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                """
                Get-Service -Name EventLog |
                Select-Object Status,StartType |
                ConvertTo-Json -Compress
                """
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode != 0:

            return {
                "status": "Critical",
                "risk": "High",
                "details": result.stderr.strip(),
                "recommendation": "Verify the Windows Event Log service immediately.",
                "detection_method": "PowerShell Get-Service",
                "confidence": "0%"
            }

        data = json.loads(result.stdout)

        service_status = str(data.get("Status", "Unknown"))
        startup_type = str(data.get("StartType", "Unknown"))

        # Enum conversion
        if service_status == "4":
            service_status = "Running"
        elif service_status == "1":
            service_status = "Stopped"

        if startup_type == "2":
            startup_type = "Automatic"
        elif startup_type == "3":
            startup_type = "Manual"
        elif startup_type == "4":
            startup_type = "Disabled"

        if service_status.lower() == "running":

            return {

                "status": "Passed",
                "risk": "Low",

                "details":

                    "Windows Event Log service is running.\n\n"

                    "Service Information\n"
                    "-------------------------\n"

                    f"Status       : {service_status}\n"
                    f"Startup Type : {startup_type}",

                "recommendation":

                    "No action required.",

                "detection_method":

                    "PowerShell Get-Service",

                "confidence":

                    "100%"
            }

        return {

            "status": "Critical",
            "risk": "High",

            "details":

                "Windows Event Log service is not running.\n\n"

                "Service Information\n"
                "-------------------------\n"

                f"Status       : {service_status}\n"
                f"Startup Type : {startup_type}",

            "recommendation":

                "Start the Windows Event Log service immediately. Many Windows security features depend on this service.",

            "detection_method":

                "PowerShell Get-Service",

            "confidence":

                "100%"
        }

    except Exception as e:

        return {

            "status": "Warning",
            "risk": "Unknown",

            "details":

                f"Windows Event Log check failed.\n\n{e}",

            "recommendation":

                "Verify the Windows Event Log service manually.",

            "detection_method":

                "PowerShell Get-Service",

            "confidence":

                "0%"
        }