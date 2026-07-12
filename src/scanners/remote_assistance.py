"""
Remote Assistance status check.

BEFORE: spawned PowerShell just to read one DWORD registry value.

AFTER: reads it directly via `winreg` -- no subprocess.
"""

import winreg


_KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"
_VALUE_NAME = "fAllowToGetHelp"


def check_remote_assistance():

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _KEY_PATH) as key:
            value, _ = winreg.QueryValueEx(key, _VALUE_NAME)

        if value == 0:
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Remote Assistance is disabled.",
                "recommendation": "No action required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        elif value == 1:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Remote Assistance is enabled.",
                "recommendation": "Disable Remote Assistance if it is not required.",
                "detection_method": "Registry",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Remote Assistance status.",
            "recommendation": "Verify Remote Assistance manually.",
            "detection_method": "Registry",
            "confidence": "70%"
        }

    except FileNotFoundError:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Remote Assistance status (registry value not found).",
            "recommendation": "Verify Remote Assistance manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Remote Assistance check failed: {e}",
            "recommendation": "Verify Remote Assistance manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }
