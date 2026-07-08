import subprocess


def check_file_printer_sharing():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Where-Object {$_.Enabled -eq 'True'}).Count"
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
                    "details": "File and Printer Sharing is enabled.",
                    "recommendation": "Disable File and Printer Sharing unless it is required on trusted networks.",
                    "detection_method": "Windows Firewall Rules",
                    "confidence": "100%"
                }

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "File and Printer Sharing is disabled.",
                "recommendation": "No action required.",
                "detection_method": "Windows Firewall Rules",
                "confidence": "100%"
            }

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine File and Printer Sharing status.",
            "recommendation": "Verify File and Printer Sharing manually.",
            "detection_method": "Windows Firewall Rules",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"File and Printer Sharing check failed: {e}",
            "recommendation": "Verify File and Printer Sharing manually.",
            "detection_method": "Windows Firewall Rules",
            "confidence": "0%"
        }