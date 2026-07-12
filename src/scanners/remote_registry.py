"""
Remote Registry service check.

BEFORE: spawned PowerShell to run `(Get-Service RemoteRegistry).Status`.

AFTER: reads the same information via `psutil.win_service_get()` -- an
in-process Win32 Service Control Manager call, no subprocess at all.
"""

from .service_utils import get_service_info


def check_remote_registry():

    try:
        info = get_service_info("RemoteRegistry")

        if info.error:
            raise RuntimeError(info.error)

        if info.status == "running":
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Remote Registry service is currently running.",
                "recommendation": "Disable the Remote Registry service unless it is required for administration.",
                "detection_method": "Windows Service",
                "confidence": "100%"
            }

        elif info.status in ("stopped", "not_installed"):
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
                "details": f"Unexpected service status: {info.status}",
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
