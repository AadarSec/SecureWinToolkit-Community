"""
Windows Event Log service check.

BEFORE: spawned PowerShell (`Get-Service -Name EventLog | ... | ConvertTo-Json`).

AFTER: reads the same information via `psutil.win_service_get()` -- no
subprocess.
"""

from .service_utils import get_service_info


def check_windows_event_log():

    try:
        info = get_service_info("EventLog")

        if info.error or not info.exists:
            return {
                "status": "Critical",
                "risk": "High",
                "details": info.error or "Windows Event Log service could not be found.",
                "recommendation": "Verify the Windows Event Log service immediately.",
                "detection_method": "Windows Service",
                "confidence": "0%"
            }

        service_status = info.status.title()
        startup_type = info.start_type.title()

        if info.status == "running":
            return {
                "status": "Passed",
                "risk": "Low",
                "details":
                    "Windows Event Log service is running.\n\n"
                    "Service Information\n"
                    "-------------------------\n"
                    f"Status       : {service_status}\n"
                    f"Startup Type : {startup_type}",
                "recommendation": "No action required.",
                "detection_method": "Windows Service",
                "confidence": "100%"
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
                "Start the Windows Event Log service immediately. Many Windows security features "
                "depend on this service.",
            "detection_method": "Windows Service",
            "confidence": "100%"
        }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Windows Event Log check failed.\n\n{e}",
            "recommendation": "Verify the Windows Event Log service manually.",
            "detection_method": "Windows Service",
            "confidence": "0%"
        }
