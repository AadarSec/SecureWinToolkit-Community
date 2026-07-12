"""
Print Spooler service check.

BEFORE: spawned PowerShell (`Get-Service -Name Spooler | ... | ConvertTo-Json`)
just to read status + start type, then manually decoded PowerShell's numeric
service-status enum values.

AFTER: reads the same information via `psutil.win_service_get()` -- no
subprocess, and psutil already returns human-readable strings so the old
enum-decoding ("4" -> "Running", "2" -> "Automatic", etc.) is unnecessary.
"""

from .service_utils import get_service_info


def check_print_spooler():

    try:
        info = get_service_info("Spooler")

        if info.error:
            raise RuntimeError(info.error)

        service_status = info.status.title() if info.status else "Unknown"
        startup_type = info.start_type.title() if info.start_type else "Unknown"

        if info.status == "running":
            return {
                "status": "Warning",
                "risk": "Medium",
                "details":
                    "Print Spooler service is currently running.\n\n"
                    "Service Information\n"
                    "-------------------------\n"
                    f"Status       : {service_status}\n"
                    f"Startup Type : {startup_type}",
                "recommendation":
                    "If this computer does not require printing, disable the Print Spooler "
                    "service to reduce the attack surface.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        return {
            "status": "Passed",
            "risk": "Low",
            "details":
                "Print Spooler service is not running.\n\n"
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
            "details": f"Print Spooler check failed:\n\n{e}",
            "recommendation": "Verify the Print Spooler service manually.",
            "detection_method": "Windows Service",
            "confidence": "0%"
        }
