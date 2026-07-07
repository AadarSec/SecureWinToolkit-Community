import subprocess


def check_firewall():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetFirewallProfile | Select-Object Name,Enabled"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout

        enabled_profiles = output.count("True")

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