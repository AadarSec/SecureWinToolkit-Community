import json
from .powershell_utils import run_ps


def _run_ps(command, timeout=20):
    # Delegates to the shared, CREATE_NO_WINDOW-enabled helper
    # (see powershell_utils.py) instead of spawning its own
    # subprocess directly.
    result = run_ps(command, timeout)
    return result.stdout, result.stderr, result.returncode


def check_credential_guard():

    # ---------------- METHOD 1: Win32_DeviceGuard (correct namespace) ----------------
    # Win32_DeviceGuard does NOT live in the default root\cimv2 namespace.
    # It lives in root\Microsoft\Windows\DeviceGuard. Querying without the
    # correct -Namespace returns "Invalid Class" on many systems.

    try:
        command = (
            "Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' "
            "-ClassName Win32_DeviceGuard -ErrorAction Stop | "
            "Select-Object SecurityServicesConfigured, SecurityServicesRunning | "
            "ConvertTo-Json -Compress"
        )

        output, err, code = _run_ps(command)

        if code == 0 and output:

            data = json.loads(output)

            configured = data.get("SecurityServicesConfigured", [])
            running = data.get("SecurityServicesRunning", [])

            # PowerShell may return int instead of list when there's only one value
            if isinstance(configured, int):
                configured = [configured]
            if isinstance(running, int):
                running = [running]
            if configured is None:
                configured = []
            if running is None:
                running = []

            # 1 = Credential Guard
            credential_guard_configured = 1 in configured
            credential_guard_running = 1 in running

            if credential_guard_configured and credential_guard_running:

                return {
                    "status": "Passed",
                    "risk": "Low",
                    "details":
                        "Credential Guard is configured and running.\n\n"
                        "Protection Status\n"
                        "-------------------------\n"
                        "Configured : Yes\n"
                        "Running    : Yes",
                    "recommendation": "No action required.",
                    "detection_method": "Win32_DeviceGuard (root\\Microsoft\\Windows\\DeviceGuard)",
                    "confidence": "100%"
                }

            return {
                "status": "Warning",
                "risk": "Medium",
                "details":
                    "Credential Guard is not fully enabled.\n\n"
                    "Protection Status\n"
                    "-------------------------\n"
                    f"Configured : {'Yes' if credential_guard_configured else 'No'}\n"
                    f"Running    : {'Yes' if credential_guard_running else 'No'}",
                "recommendation": "Enable Windows Credential Guard to protect credentials from theft.",
                "detection_method": "Win32_DeviceGuard (root\\Microsoft\\Windows\\DeviceGuard)",
                "confidence": "100%"
            }

    except Exception:
        pass

    # ---------------- METHOD 2: Registry (LSA CredentialGuard flag) ----------------

    try:
        command = (
            "(Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' "
            "-Name 'LsaCfgFlags' -ErrorAction SilentlyContinue).LsaCfgFlags"
        )

        output, err, code = _run_ps(command)

        if output in ("1", "2"):
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Credential Guard is configured via policy (detected via registry).",
                "recommendation": "No action required.",
                "detection_method": "Registry (LSA\\LsaCfgFlags)",
                "confidence": "75%"
            }

        elif output == "0":
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": "Credential Guard is explicitly disabled via policy (detected via registry).",
                "recommendation": "Enable Windows Credential Guard to protect credentials from theft.",
                "detection_method": "Registry (LSA\\LsaCfgFlags)",
                "confidence": "75%"
            }

    except Exception:
        pass

    # ---------------- METHOD 3: Edition check ----------------
    # Credential Guard requires Windows 10/11 Enterprise, Education, or Pro
    # with virtualization-based security support. Home edition never
    # supports it, so surface a clearer message instead of "Unknown".

    try:
        output, err, code = _run_ps("(Get-ComputerInfo).WindowsEditionId")

        if "home" in output.lower():
            return {
                "status": "Warning",
                "risk": "Medium",
                "details": f"Credential Guard is not available on this Windows edition ({output}).",
                "recommendation": "Credential Guard requires Windows Pro, Enterprise, or Education. "
                                   "Upgrade the edition if this protection is required.",
                "detection_method": "PowerShell (Get-ComputerInfo edition)",
                "confidence": "80%"
            }

    except Exception:
        pass

    # ---------------- ALL METHODS FAILED ----------------

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "Credential Guard status could not be determined on this system.",
        "recommendation": "Run SecureWin Toolkit as Administrator, or check Credential Guard "
                           "status manually via System Information (msinfo32).",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
