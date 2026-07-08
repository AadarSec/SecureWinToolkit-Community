import subprocess


def _run_ps(command, timeout=15):

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return result.stdout.strip(), result.stderr.strip()


def check_smartscreen():

    # ---------------- METHOD 1: Windows Security (App Install Control) ----------------

    try:
        script = (
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\SmartScreen' "
            "-Name 'ConfigureAppInstallControlEnabled' -ErrorAction SilentlyContinue)."
            "ConfigureAppInstallControlEnabled"
        )

        output, err = _run_ps(script)

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "SmartScreen is enabled (Windows Security).",
                "recommendation": "No action required.",
                "detection_method": "Registry (Windows Defender\\SmartScreen)",
                "confidence": "95%"
            }

        elif output == "0":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "SmartScreen is disabled (Windows Security).",
                "recommendation": "Enable SmartScreen via Windows Security > App & browser control "
                                   "to help block malicious apps and sites.",
                "detection_method": "Registry (Windows Defender\\SmartScreen)",
                "confidence": "95%"
            }

    except Exception:
        pass

    # ---------------- METHOD 2: Explorer (per-user setting) ----------------

    try:
        script = (
            "(Get-ItemProperty -Path "
            "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer' "
            "-Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue).SmartScreenEnabled"
        )

        output, err = _run_ps(script)

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

    # ---------------- METHOD 3: Group Policy ----------------

    try:
        script = (
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' "
            "-Name 'EnableSmartScreen' -ErrorAction SilentlyContinue).EnableSmartScreen"
        )

        output, err = _run_ps(script)

        if output == "1":
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "SmartScreen is enabled via Group Policy.",
                "recommendation": "No action required.",
                "detection_method": "Registry (Group Policy)",
                "confidence": "75%"
            }

        elif output == "0":
            return {
                "status": "Critical",
                "risk": "High",
                "details": "SmartScreen is disabled via Group Policy.",
                "recommendation": "Enable SmartScreen via Group Policy or Windows Security settings.",
                "detection_method": "Registry (Group Policy)",
                "confidence": "75%"
            }

    except Exception:
        pass

    # ---------------- ALL METHODS FAILED ----------------

    return {
        "status": "Warning",
        "risk": "Unknown",
        "details": "SmartScreen status could not be determined via any registry location. This "
                   "may indicate default (unconfigured) settings.",
        "recommendation": "Check SmartScreen settings manually via Windows Security > App & "
                           "browser control.",
        "detection_method": "None (all methods failed)",
        "confidence": "0%"
    }
