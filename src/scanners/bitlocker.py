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


def check_bitlocker():

    admin = is_admin()

    # ---------------- METHOD 1: WMI Win32_EncryptableVolume ----------------
    # This works consistently across Home, Pro, and Enterprise (Home uses
    # "Device Encryption" which is built on the same BitLocker APIs) and
    # does not require the BitLocker PowerShell module to be present.

    try:
        script = (
            "$vol = Get-CimInstance -Namespace "
            "'root\\cimv2\\security\\MicrosoftVolumeEncryption' "
            "-ClassName Win32_EncryptableVolume "
            "-Filter \"DriveLetter='$env:SystemDrive'\" -ErrorAction Stop;"
            "if ($vol) { $vol.GetProtectionStatus().ProtectionStatus } else { 'NONE' }"
        )

        output, err, code = _run_ps(script)

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "BitLocker (or Device Encryption) protection is ON for the system drive.",
                "recommendation": "No action required.",
                "detection_method": "WMI (Win32_EncryptableVolume)",
                "confidence": "95%"
            }

        elif output == "0":
            return {
                "status": "Warning",
                "risk": "High",
                "details": "BitLocker (or Device Encryption) protection is OFF for the system drive.",
                "recommendation": "Enable BitLocker/Device Encryption to protect data if the device "
                                   "is lost or stolen.",
                "detection_method": "WMI (Win32_EncryptableVolume)",
                "confidence": "95%"
            }

        elif output == "NONE":
            # WMI class exists but returned no volume for the system drive.
            # This usually means the drive isn't encryptable/managed by
            # BitLocker at all, or the query needs elevation. Fall through.
            pass

    except Exception:
        pass

    # ---------------- METHOD 2: Get-BitLockerVolume (BitLocker module) ----------------
    # Not present on Windows Home, so this is tried second rather than first.

    try:
        output, err, code = _run_ps(
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus"
        )

        if output == "On":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "BitLocker protection is ON for the system drive.",
                "recommendation": "No action required.",
                "detection_method": "PowerShell (Get-BitLockerVolume)",
                "confidence": "98%"
            }

        elif output == "Off":
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

    # ---------------- METHOD 3: manage-bde -status ----------------
    # Requires administrator privileges on most systems, so it's used as a
    # secondary check rather than the primary source of truth.

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

    # ---------------- METHOD 4: Edition-aware fallback ----------------
    # If every method above failed to produce a definitive answer, give a
    # clear, edition-specific reason instead of a generic "Unknown".

    try:
        edition, err, code = _run_ps("(Get-ComputerInfo).WindowsEditionId")
    except Exception:
        edition = ""

    if not admin:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "BitLocker status could not be confirmed because this check was not run "
                       "with administrator privileges.",
            "recommendation": "Run SecureWin Toolkit as Administrator to accurately detect "
                               "BitLocker/Device Encryption status.",
            "detection_method": "None (administrator privileges required)",
            "confidence": "0%",
            "admin_required": True
        }

    if "home" in edition.lower():
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"BitLocker status could not be determined. This device is running "
                       f"{edition}, which uses Device Encryption instead of full BitLocker, "
                       f"and it may not be available on this hardware.",
            "recommendation": "Check Settings > Privacy & Security > Device Encryption manually.",
            "detection_method": "None (all methods failed)",
            "confidence": "0%"
        }

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "BitLocker status could not be determined on this system.",
        "recommendation": "Check BitLocker status manually via Control Panel > BitLocker Drive "
                           "Encryption.",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
