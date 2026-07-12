"""
Remote Desktop (RDP) status check.

BEFORE: spawned PowerShell just to read one DWORD registry value.

AFTER: reads it directly via `winreg` -- no subprocess.
"""

import winreg


_KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
_VALUE_NAME = "fDenyTSConnections"


def check_rdp():

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _KEY_PATH) as key:
            value, _ = winreg.QueryValueEx(key, _VALUE_NAME)

        if value == 1:
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Remote Desktop is disabled.",
                "recommendation": "No action required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        elif value == 0:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Remote Desktop is enabled.",
                "recommendation": "Disable Remote Desktop unless remote access is required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Remote Desktop status.",
            "recommendation": "Verify Remote Desktop settings manually.",
            "detection_method": "Registry",
            "confidence": "50%"
        }

    except FileNotFoundError:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Remote Desktop status (registry value not found).",
            "recommendation": "Verify Remote Desktop settings manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Remote Desktop check failed: {e}",
            "recommendation": "Verify Remote Desktop settings manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }
