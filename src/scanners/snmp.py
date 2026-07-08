import json
import subprocess


def check_snmp():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                """
                Get-Service -Name SNMP -ErrorAction SilentlyContinue |
                Select-Object Status, StartType |
                ConvertTo-Json -Compress
                """
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        output = result.stdout.strip()

        # Service not installed
        if not output:

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "SNMP service is not installed on this system.",
                "recommendation": "No action required.",
                "detection_method": "PowerShell Get-Service",
                "confidence": "100%"
            }

        data = json.loads(output)

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

                "status": "Warning",
                "risk": "Medium",

                "details":

                    "SNMP service is currently running.\n\n"

                    "Service Information\n"
                    "-------------------------\n"

                    f"Status       : {service_status}\n"
                    f"Startup Type : {startup_type}",

                "recommendation":

                    "Disable SNMP if it is not required or secure it with strong community strings and access controls.",

                "detection_method":

                    "PowerShell Get-Service",

                "confidence":

                    "100%"
            }

        return {

            "status": "Passed",
            "risk": "Low",

            "details":

                "SNMP service is installed but not running.\n\n"

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

    except Exception as e:

        return {

            "status": "Warning",
            "risk": "Unknown",

            "details":

                f"SNMP check failed.\n\n{e}",

            "recommendation":

                "Verify the SNMP service manually.",

            "detection_method":

                "PowerShell Get-Service",

            "confidence":

                "0%"
        }