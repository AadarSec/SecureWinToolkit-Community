import subprocess


def _run_ps(command, timeout=15):

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return result.stdout.strip(), result.stderr.strip()


def check_tpm():

    # ---------------- METHOD 1: Get-Tpm ----------------

    try:
        present, err1 = _run_ps("(Get-Tpm).TpmPresent")

        if present.lower() == "true":

            ready, err2 = _run_ps("(Get-Tpm).TpmReady")

            if ready.lower() == "true":
                return {
                    "status": "Passed",
                    "risk": "Low",
                    "details": "TPM is present and ready.",
                    "recommendation": "No action required.",
                    "detection_method": "PowerShell (Get-Tpm)",
                    "confidence": "98%"
                }

            else:
                return {
                    "status": "Warning",
                    "risk": "Medium",
                    "details": "TPM is present but not fully ready/initialized.",
                    "recommendation": "Initialize the TPM via tpm.msc or UEFI/BIOS settings.",
                    "detection_method": "PowerShell (Get-Tpm)",
                    "confidence": "95%"
                }

        elif present.lower() == "false":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "No TPM was detected on this device.",
                "recommendation": "Enable TPM in UEFI/BIOS settings if supported by the hardware.",
                "detection_method": "PowerShell (Get-Tpm)",
                "confidence": "95%"
            }

    except Exception:
        pass

    # ---------------- METHOD 2: WMI Win32_Tpm ----------------

    try:
        script = (
            "$tpm = Get-CimInstance -Namespace 'root\\cimv2\\security\\MicrosoftTpm' "
            "-ClassName Win32_Tpm -ErrorAction SilentlyContinue;"
            "if ($tpm) { $tpm.IsEnabled_InitialValue } else { 'NONE' }"
        )

        output, err = _run_ps(script)

        if output.lower() == "true":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "TPM is present and enabled (detected via WMI).",
                "recommendation": "No action required.",
                "detection_method": "WMI (Win32_Tpm)",
                "confidence": "80%"
            }

        elif output.lower() == "false":
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "TPM is present but disabled (detected via WMI).",
                "recommendation": "Enable TPM in UEFI/BIOS settings.",
                "detection_method": "WMI (Win32_Tpm)",
                "confidence": "80%"
            }

    except Exception:
        pass

    # ---------------- METHOD 3: Registry (driver presence only) ----------------

    try:
        script = (
            "Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TPM'"
        )

        output, err = _run_ps(script)

        if output.lower() == "true":
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "A TPM driver was found in the registry, but active status could not be "
                           "confirmed. This is a low-confidence indicator only.",
                "recommendation": "Confirm TPM status manually via tpm.msc or UEFI/BIOS settings.",
                "detection_method": "Registry (driver presence)",
                "confidence": "50%"
            }

    except Exception:
        pass

    # ---------------- ALL METHODS FAILED ----------------

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "TPM status could not be determined on this system.",
        "recommendation": "Run SecureWin Toolkit as Administrator, or check TPM status manually via tpm.msc.",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
