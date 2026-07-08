import subprocess


def check_smbv1():

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        state = result.stdout.strip().lower()

        # -----------------------------
        # DEBUG OUTPUT
        # -----------------------------
        print("\n========== SMBv1 DEBUG ==========")
        print("Return Code :", result.returncode)
        print("STDOUT      :", repr(result.stdout))
        print("STDERR      :", repr(result.stderr))
        print("STATE       :", repr(state))
        print("=================================\n")

        # -----------------------------
        # SMBv1 Disabled
        # -----------------------------
        if state in [
            "disabled",
            "disabledwithpayloadremoved"
        ]:

            return {
                "status": "Passed",
                "risk": "Low",
                "details": "SMBv1 is disabled or not installed.",
                "recommendation": "No action required.",
                "detection_method": "Windows Optional Feature",
                "confidence": "100%"
            }

        # -----------------------------
        # SMBv1 Enabled
        # -----------------------------
        elif state == "enabled":

            return {
                "status": "Critical",
                "risk": "High",
                "details": "SMBv1 is enabled. This legacy protocol is vulnerable to attacks such as WannaCry.",
                "recommendation": "Disable SMBv1 immediately unless required by legacy systems.",
                "detection_method": "Windows Optional Feature",
                "confidence": "100%"
            }

        # -----------------------------
        # Unknown state
        # -----------------------------
        elif state:

            return {
                "status": "Warning",
                "risk": "Unknown",
                "details": f"Unexpected SMBv1 state: {state}",
                "recommendation": "Verify SMBv1 configuration manually.",
                "detection_method": "Windows Optional Feature",
                "confidence": "80%"
            }

        # -----------------------------
        # Empty output
        # -----------------------------
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "PowerShell returned an empty SMBv1 state.",
            "recommendation": "Verify SMBv1 configuration manually.",
            "detection_method": "Windows Optional Feature",
            "confidence": "50%"
        }

    except Exception as e:

        print("\n========== SMBv1 EXCEPTION ==========")
        print(e)
        print("=====================================\n")

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"SMBv1 check failed: {e}",
            "recommendation": "Verify SMBv1 configuration manually.",
            "detection_method": "Windows Optional Feature",
            "confidence": "0%"
        }