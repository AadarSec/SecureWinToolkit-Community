import subprocess


def check_tpm():

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Tpm).TpmPresent"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        present = result.stdout.strip().lower()

        if present == "true":

            result2 = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-Tpm).TpmReady"
                ],
                capture_output=True,
                text=True,
                timeout=15
            )

            ready = result2.stdout.strip().lower()

            if ready == "true":
                return {
                    "status": "Passed",
                    "risk": "Low",
                    "details": "TPM is present and ready.",
                    "recommendation": "No action needed."
                }

            else:
                return {
                    "status": "Warning",
                    "risk": "Medium",
                    "details": "TPM is present but not fully ready/initialized.",
                    "recommendation": "Initialize the TPM via tpm.msc or UEFI/BIOS settings."
                }

        else:
            return {
                "status": "Critical",
                "risk": "High",
                "details": "No TPM was detected on this device.",
                "recommendation": "Enable TPM in UEFI/BIOS settings if supported by the hardware."
            }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"TPM check failed: {e}",
            "recommendation": "Verify TPM status manually via tpm.msc."
        }
