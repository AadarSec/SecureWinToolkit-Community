import subprocess


def check_bitlocker():

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout.strip()

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "BitLocker protection is ON for the system drive.",
                "recommendation": "No action needed."
            }

        elif output == "0":
            return {
                "status": "Warning",
                "risk": "High",
                "details": "BitLocker protection is OFF for the system drive.",
                "recommendation": "Enable BitLocker to protect data if the device is lost or stolen."
            }

        else:
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Could not determine BitLocker status.",
                "recommendation": "Check BitLocker status manually via Control Panel > BitLocker Drive Encryption."
            }

    except Exception as e:
        return {
            "status": "Critical",
            "risk": "Unknown",
            "details": f"BitLocker check failed: {e}",
            "recommendation": "Verify BitLocker availability manually; this device may not support it."
        }
