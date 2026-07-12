"""
Windows Firewall profile check.

Now uses the shared run_ps() helper (see powershell_utils.py) instead of
a hand-rolled subprocess.run() call: same behavior, but the child process
no longer flashes a console window and spawns slightly faster.
"""

from .powershell_utils import run_ps


def check_firewall():

    try:
        result = run_ps("Get-NetFirewallProfile | Select-Object Name,Enabled")

        if not result.ok:
            raise RuntimeError(result.stderr or "Get-NetFirewallProfile failed")

        enabled_profiles = result.stdout.count("True")

        if enabled_profiles == 3:
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "All Windows Firewall profiles (Domain, Private and Public) are enabled.",
                "recommendation": "No action required."
            }

        elif enabled_profiles > 0:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": f"{enabled_profiles} of 3 Windows Firewall profiles are enabled.",
                "recommendation": "Enable all Windows Firewall profiles for maximum protection."
            }

        else:
            return {
                "status": "Critical",
                "risk": "High",
                "details": "Windows Firewall is disabled on all network profiles.",
                "recommendation": "Enable Windows Firewall immediately."
            }

    except Exception:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Windows Firewall status.",
            "recommendation": "Verify Windows Firewall configuration manually."
        }
