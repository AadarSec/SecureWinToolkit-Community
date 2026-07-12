"""
WinRM (Windows Remote Management) service check.

BEFORE: spawned PowerShell to run `(Get-Service WinRM).Status`.

AFTER: reads the same information via `psutil.win_service_get()` -- an
in-process Win32 Service Control Manager call, no subprocess at all.
"""

from .service_utils import get_service_info


def check_winrm():

    try:
        info = get_service_info("WinRM")

        if info.error:
            raise RuntimeError(info.error)

        if info.status == "running":
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Windows Remote Management (WinRM) service is running.",
                "recommendation": "Disable WinRM if remote management is not required.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        elif info.status in ("stopped", "not_installed"):
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
                "details": f"Unexpected WinRM service state: {info.status}",
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
