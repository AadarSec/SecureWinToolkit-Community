"""
UAC (User Account Control) status check.

BEFORE: spawned powershell.exe + Get-ItemProperty just to read a single
DWORD registry value.

AFTER: reads the same value directly via the stdlib `winreg` module.
No subprocess, no PowerShell/.NET startup cost -- this now runs in well
under a millisecond instead of ~150-400ms.
"""

import winreg


_KEY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_VALUE_NAME = "EnableLUA"


def check_uac():

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _KEY_PATH) as key:
            value, _ = winreg.QueryValueEx(key, _VALUE_NAME)

        if value == 1:
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "User Account Control (UAC) is enabled.",
                "recommendation": "No action needed."
            }

        elif value == 0:
            return {
                "status": "Critical",
                "risk": "High",
                "details": "User Account Control (UAC) is disabled.",
                "recommendation": "Enable UAC via Control Panel > User Accounts > Change UAC settings "
                                   "to prevent unauthorized system changes."
            }

        else:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "UAC status could not be determined.",
                "recommendation": "Check UAC settings manually via Control Panel."
            }

    except FileNotFoundError:
        return {
            "status": "Warning",
            "risk": "Medium",
            "details": "UAC status could not be determined (registry value not found).",
            "recommendation": "Check UAC settings manually via Control Panel."
        }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"UAC check failed: {e}",
            "recommendation": "Verify UAC settings manually via Control Panel."
        }
