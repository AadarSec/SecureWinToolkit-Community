import subprocess


def check_network_discovery():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Where-Object {$_.Enabled -eq 'True'}).Count"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        count = result.stdout.strip()

        if count.isdigit():

            enabled_rules = int(count)

            if enabled_rules > 0:

                return {
                    "status": "Warning",
                    "risk": "Medium",
                    "details": "Network Discovery is enabled.",
                    "recommendation": "Disable Network Discovery on untrusted or public networks.",
                    "detection_method": "Windows Firewall Rules",
                    "confidence": "100%"
                }

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Network Discovery is disabled.",
                "recommendation": "No action required.",
                "detection_method": "Windows Firewall Rules",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine Network Discovery status.",
            "recommendation": "Verify Network Discovery manually.",
            "detection_method": "Windows Firewall Rules",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Network Discovery check failed: {e}",
            "recommendation": "Verify Network Discovery manually.",
            "detection_method": "Windows Firewall Rules",
            "confidence": "0%"
        }