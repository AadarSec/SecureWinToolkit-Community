import subprocess
import re


def _run_ps(command, timeout=15):

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return result.stdout.strip(), result.stderr.strip()


def check_bitlocker():

    # ---------------- METHOD 1: Get-BitLockerVolume ----------------

    try:
        output, err = _run_ps(
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"
        )

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "BitLocker protection is ON for the system drive.",
                "recommendation": "No action required.",
                "detection_method": "PowerShell (Get-BitLockerVolume)",
                "confidence": "98%"
            }

        elif output == "0":
            return {
                "status": "Warning",
                "risk": "High",
                "details": "BitLocker protection is OFF for the system drive.",
                "recommendation": "Enable BitLocker to protect data if the device is lost or stolen.",
                "detection_method": "PowerShell (Get-BitLockerVolume)",
                "confidence": "98%"
            }

    except Exception:
        pass

    # ---------------- METHOD 2: manage-bde -status ----------------

    try:
        result = subprocess.run(
            ["manage-bde", "-status", "%SystemDrive%"],
            capture_output=True,
            text=True,
            timeout=15,
            shell=True
        )

        output = result.stdout

        if "Protection On" in output:
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "BitLocker protection is ON for the system drive (detected via manage-bde).",
                "recommendation": "No action required.",
                "detection_method": "Command Line (manage-bde)",
                "confidence": "88%"
            }

        elif "Protection Off" in output:
            return {
                "status": "Warning",
                "risk": "High",
                "details": "BitLocker protection is OFF for the system drive (detected via manage-bde).",
                "recommendation": "Enable BitLocker to protect data if the device is lost or stolen.",
                "detection_method": "Command Line (manage-bde)",
                "confidence": "88%"
            }

    except Exception:
        pass

    # ---------------- METHOD 3: WMI Win32_EncryptableVolume ----------------

    try:
        script = (
            "$vol = Get-CimInstance -Namespace 'root\\cimv2\\security\\MicrosoftVolumeEncryption' "
            "-ClassName Win32_EncryptableVolume -Filter \"DriveLetter='$env:SystemDrive'\";"
            "if ($vol) { $vol.GetProtectionStatus().ProtectionStatus } else { 'NONE' }"
        )

        output, err = _run_ps(script)

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "BitLocker protection is ON for the system drive (detected via WMI).",
                "recommendation": "No action required.",
                "detection_method": "WMI (Win32_EncryptableVolume)",
                "confidence": "75%"
            }

        elif output == "0":
            return {
                "status": "Warning",
                "risk": "High",
                "details": "BitLocker protection is OFF for the system drive (detected via WMI).",
                "recommendation": "Enable BitLocker to protect data if the device is lost or stolen.",
                "detection_method": "WMI (Win32_EncryptableVolume)",
                "confidence": "75%"
            }

    except Exception:
        pass

    # ---------------- ALL METHODS FAILED ----------------

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "BitLocker status could not be determined. This usually requires administrator "
                   "privileges, or BitLocker may not be available on this edition of Windows.",
        "recommendation": "Run SecureWin Toolkit as Administrator, or check BitLocker status manually "
                           "via Control Panel > BitLocker Drive Encryption.",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
