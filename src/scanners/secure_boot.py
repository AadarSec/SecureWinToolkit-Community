import subprocess


def check_secure_boot():

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Confirm-SecureBootUEFI"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout.strip()

        if output.lower() == "true":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Secure Boot is enabled.",
                "recommendation": "No action needed."
            }

        elif output.lower() == "false":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "Secure Boot is disabled.",
                "recommendation": "Enable Secure Boot in UEFI/BIOS settings to prevent unauthorized "
                                   "bootloaders and rootkits."
            }

        else:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Secure Boot status could not be determined (may not be supported on this device).",
                "recommendation": "Check UEFI/BIOS settings manually to confirm Secure Boot availability."
            }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Secure Boot check failed: {e}",
            "recommendation": "Verify Secure Boot manually via UEFI/BIOS settings."
        }
