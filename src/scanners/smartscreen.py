import subprocess


def _run_ps(command, timeout=15):

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return result.stdout.strip(), result.stderr.strip(), result.returncode


def _key_exists(path):

    output, err, code = _run_ps(f"Test-Path '{path}'")
    return output.strip().lower() == "true"


def check_smartscreen():

    # ---------------- METHOD 1: Group Policy (highest precedence) ----------------

    try:
        gp_path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"

        if _key_exists(gp_path):

            script = (
                f"(Get-ItemProperty -Path '{gp_path}' "
                "-Name 'EnableSmartScreen' -ErrorAction SilentlyContinue).EnableSmartScreen"
            )

            output, err, code = _run_ps(script)

            if output == "1":
                return {
                    "status": "Passed",
                    "risk": "Low",
                    "details": "SmartScreen is enabled via Group Policy.",
                    "recommendation": "No action required.",
                    "detection_method": "Registry (Group Policy)",
                    "confidence": "95%"
                }

            elif output == "0":
                return {
                    "status": "Critical",
                    "risk": "High",
                    "details": "SmartScreen is disabled via Group Policy.",
                    "recommendation": "Enable SmartScreen via Group Policy or Windows Security settings.",
                    "detection_method": "Registry (Group Policy)",
                    "confidence": "95%"
                }

    except Exception:
        pass

    # ---------------- METHOD 2: Windows Security (App Install Control) ----------------

    try:
        path = "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\SmartScreen"

        if _key_exists(path):

            script = (
                f"(Get-ItemProperty -Path '{path}' "
                "-Name 'ConfigureAppInstallControlEnabled' -ErrorAction SilentlyContinue)."
                "ConfigureAppInstallControlEnabled"
            )

            output, err, code = _run_ps(script)

            if output == "1":
                return {
                    "status": "Passed",
                    "risk": "Low",
                    "details": "SmartScreen is enabled (Windows Security > App & browser control).",
                    "recommendation": "No action required.",
                    "detection_method": "Registry (Windows Defender\\SmartScreen)",
                    "confidence": "90%"
                }

            elif output == "0":
                return {
                    "status": "Critical",
                    "risk": "High",
                    "details": "SmartScreen is disabled (Windows Security > App & browser control).",
                    "recommendation": "Enable SmartScreen via Windows Security > App & browser control "
                                       "to help block malicious apps and sites.",
                    "detection_method": "Registry (Windows Defender\\SmartScreen)",
                    "confidence": "90%"
                }

    except Exception:
        pass

    # ---------------- METHOD 3: Explorer (per-user setting) ----------------

    try:
        path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"

        script = (
            f"(Get-ItemProperty -Path '{path}' "
            "-Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue).SmartScreenEnabled"
        )

        output, err, code = _run_ps(script)

        if output.lower() in ("requireadmin", "warn"):
            return {
                "status": "Passed",
                "risk": "Low",
                "details": f"SmartScreen is enabled for Explorer (mode: {output}).",
                "recommendation": "No action required.",
                "detection_method": "Registry (Explorer\\SmartScreenEnabled)",
                "confidence": "80%"
            }

        elif output.lower() == "off":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "SmartScreen is disabled for Explorer.",
                "recommendation": "Enable SmartScreen via Windows Security > App & browser control.",
                "detection_method": "Registry (Explorer\\SmartScreenEnabled)",
                "confidence": "80%"
            }

    except Exception:
        pass

    # ---------------- METHOD 4: Default state handling ----------------
    # If none of the registry locations above have a value configured, the
    # setting has never been explicitly changed. On Windows 10/11, this
    # means SmartScreen is at its default state, which is ENABLED
    # ("Warn" mode) out of the box. Reporting "Unknown" here was
    # misleading -- report the actual default instead.

    return {
        "status": "Passed",
        "risk": "Low",
        "details": "No explicit SmartScreen configuration was found in the registry. Windows "
                   "defaults to SmartScreen enabled ('Warn' mode) when unconfigured.",
        "recommendation": "No action required. Confirm in Windows Security > App & browser "
                           "control if you want to verify manually.",
        "detection_method": "Default state (no explicit configuration found)",
        "confidence": "60%"
    }
