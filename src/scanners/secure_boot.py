import subprocess


def _run_ps(command, timeout=15):

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return result.stdout.strip(), result.stderr.strip()


def check_secure_boot():

    # ---------------- METHOD 1: Confirm-SecureBootUEFI ----------------
    # Throws an exception on Legacy BIOS systems, so we check stderr too.

    try:
        output, err = _run_ps("Confirm-SecureBootUEFI")

        if output.lower() == "true":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Secure Boot is enabled.",
                "recommendation": "No action required.",
                "detection_method": "PowerShell (Confirm-SecureBootUEFI)",
                "confidence": "98%"
            }

        elif output.lower() == "false":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "Secure Boot is disabled.",
                "recommendation": "Enable Secure Boot in UEFI/BIOS settings to prevent unauthorized "
                                   "bootloaders and rootkits.",
                "detection_method": "PowerShell (Confirm-SecureBootUEFI)",
                "confidence": "98%"
            }

        # If output is empty and no clear true/false, likely a Legacy BIOS
        # exception went to stderr — fall through to Method 2.

    except Exception:
        pass

    # ---------------- METHOD 2: Registry ----------------

    try:
        script = (
            "(Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State' "
            "-Name 'UEFISecureBootEnabled' -ErrorAction SilentlyContinue)."
            "UEFISecureBootEnabled"
        )

        output, err = _run_ps(script)

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Secure Boot is enabled (detected via registry).",
                "recommendation": "No action required.",
                "detection_method": "Registry (SecureBoot\\State)",
                "confidence": "85%"
            }

        elif output == "0":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "Secure Boot is disabled (detected via registry).",
                "recommendation": "Enable Secure Boot in UEFI/BIOS settings to prevent unauthorized "
                                   "bootloaders and rootkits.",
                "detection_method": "Registry (SecureBoot\\State)",
                "confidence": "85%"
            }

    except Exception:
        pass

    # ---------------- METHOD 3: Firmware type ----------------
    # If the registry key doesn't exist at all, the device is very likely
    # running Legacy BIOS, where Secure Boot does not apply.

    try:
        output, err = _run_ps("(Get-ComputerInfo).BiosFirmwareType")

        if "legacy" in output.lower() or "bios" in output.lower():
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "This device appears to use Legacy BIOS rather than UEFI, so Secure "
                           "Boot is not applicable.",
                "recommendation": "If hardware supports it, consider switching to UEFI mode to "
                                   "enable Secure Boot.",
                "detection_method": "PowerShell (Get-ComputerInfo firmware type)",
                "confidence": "70%"
            }

        elif "uefi" in output.lower():
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Device uses UEFI firmware, but Secure Boot status could not be confirmed.",
                "recommendation": "Check Secure Boot status manually in UEFI/BIOS settings.",
                "detection_method": "PowerShell (Get-ComputerInfo firmware type)",
                "confidence": "60%"
            }

    except Exception:
        pass

    # ---------------- ALL METHODS FAILED ----------------

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "Secure Boot status could not be determined on this system.",
        "recommendation": "Check Secure Boot status manually in UEFI/BIOS settings.",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
