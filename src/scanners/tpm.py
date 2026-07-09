import subprocess

from .admin_utils import is_admin


def _run_ps(command, timeout=15):

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return result.stdout.strip(), result.stderr.strip(), result.returncode


def check_tpm():

    # ---------------- METHOD 1: Get-Tpm ----------------

    try:
        present, err1, code1 = _run_ps("(Get-Tpm).TpmPresent")

        if present.lower() == "true":

            ready, err2, code2 = _run_ps("(Get-Tpm).TpmReady")

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
    # Used only when Get-Tpm itself is unavailable or errors out (for
    # example, the TPM module missing on some builds).

    try:
        script = (
            "$tpm = Get-CimInstance -Namespace 'root\\cimv2\\security\\MicrosoftTpm' "
            "-ClassName Win32_Tpm -ErrorAction Stop;"
            "if ($tpm) { \"$($tpm.IsEnabled_InitialValue)|$($tpm.IsActivated_InitialValue)\" } "
            "else { 'NONE' }"
        )

        output, err, code = _run_ps(script)

        if output and output != "NONE":

            parts = output.split("|")
            enabled = parts[0].strip().lower() == "true" if len(parts) > 0 else False
            activated = parts[1].strip().lower() == "true" if len(parts) > 1 else False

            if enabled and activated:
                return {
                    "status": "Passed",
                    "risk": "Low",
                    "details": "TPM is present, enabled, and activated (detected via WMI).",
                    "recommendation": "No action required.",
                    "detection_method": "WMI (Win32_Tpm)",
                    "confidence": "85%"
                }

            return {
                "status": "Warning",
                "risk": "Medium",
                "details":
                    "TPM is present but not fully enabled/activated (detected via WMI).\n\n"
                    f"Enabled   : {'Yes' if enabled else 'No'}\n"
                    f"Activated : {'Yes' if activated else 'No'}",
                "recommendation": "Enable and activate the TPM in UEFI/BIOS settings.",
                "detection_method": "WMI (Win32_Tpm)",
                "confidence": "85%"
            }

        elif output == "NONE":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "No TPM was detected on this device (detected via WMI).",
                "recommendation": "Enable TPM in UEFI/BIOS settings if supported by the hardware.",
                "detection_method": "WMI (Win32_Tpm)",
                "confidence": "80%"
            }

    except Exception:
        pass

    # ---------------- ALL METHODS FAILED ----------------
    # Note: the registry driver-presence fallback was intentionally removed.
    # The presence of the TPM driver key only indicates the driver is
    # installed, not that a TPM chip exists or is healthy, and it was
    # producing false positives.

    if not is_admin():
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "TPM status could not be confirmed because this check was not run with "
                       "administrator privileges.",
            "recommendation": "Run SecureWin Toolkit as Administrator to accurately detect "
                               "TPM status.",
            "detection_method": "None (administrator privileges required)",
            "confidence": "0%",
            "admin_required": True
        }

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "TPM status could not be determined on this system.",
        "recommendation": "Check TPM status manually via tpm.msc.",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
