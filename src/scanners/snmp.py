"""
SNMP service check.

BEFORE: spawned PowerShell (`Get-Service -Name SNMP | ... | ConvertTo-Json`).

AFTER: reads the same information via `psutil.win_service_get()` -- no
subprocess.
"""

from .service_utils import get_service_info


def check_snmp():

    try:
        info = get_service_info("SNMP")

        if not info.exists:
            if info.error:
                raise RuntimeError(info.error)
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "SNMP service is not installed on this system.",
                "recommendation": "No action required.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        service_status = info.status.title()
        startup_type = info.start_type.title()

        if info.status == "running":
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
                    "Disable SNMP if it is not required or secure it with strong community strings "
                    "and access controls.",
                "detection_method": "Windows Service",
                "confidence": "100%"
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
            "recommendation": "No action required.",
            "detection_method": "Windows Service",
            "confidence": "100%"
        }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"SNMP check failed.\n\n{e}",
            "recommendation": "Verify the SNMP service manually.",
            "detection_method": "Windows Service",
            "confidence": "0%"
        }
