from .powershell_utils import run_ps


def _run_ps(command, timeout=20):
    # Delegates to the shared, CREATE_NO_WINDOW-enabled helper
    # (see powershell_utils.py) instead of spawning its own
    # subprocess directly.
    result = run_ps(command, timeout)
    return result.stdout, result.stderr, result.returncode


def check_smbv1():

    findings = {}

    # ---------------- METHOD 1: Windows Optional Feature ----------------

    try:
        output, err, code = _run_ps(
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
            "-ErrorAction Stop | Select-Object -ExpandProperty State"
        )

        state = output.strip().lower()

        if state in ("disabled", "disabledwithpayloadremoved"):
            findings["optional_feature"] = "Disabled"
        elif state == "enabled":
            findings["optional_feature"] = "Enabled"

    except Exception:
        pass

    # ---------------- METHOD 2: SMB Server Configuration ----------------
    # Even if the optional feature is still installed, the SMB1 protocol
    # can be separately disabled at the server-configuration level. This
    # catches that case and also works when the optional feature query
    # fails or returns nothing.

    try:
        output, err, code = _run_ps(
            "(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol"
        )

        value = output.strip().lower()

        if value == "false":
            findings["server_config"] = "Disabled"
        elif value == "true":
            findings["server_config"] = "Enabled"

    except Exception:
        pass

    # ---------------- METHOD 3: Registry ----------------
    # SMB1 can also be disabled via the LanmanServer registry key
    # independently of the two checks above. Used as a fallback signal.

    try:
        output, err, code = _run_ps(
            "(Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
            "-Name 'SMB1' -ErrorAction SilentlyContinue).SMB1"
        )

        value = output.strip()

        if value == "0":
            findings["registry"] = "Disabled"
        elif value == "1":
            findings["registry"] = "Enabled"

    except Exception:
        pass

    # ---------------- COMBINE RESULTS ----------------
    # SMB1 is only truly OFF if every method that returned a definitive
    # answer agrees it's disabled. If any method reports it's still
    # enabled, treat SMB1 as enabled (it is the more dangerous state to
    # miss). If no method returned a definitive answer, report Unknown
    # instead of silently guessing.

    if not findings:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": "Unable to determine SMBv1 status through any detection method.",
            "recommendation": "Verify SMBv1 configuration manually via "
                               "Get-WindowsOptionalFeature or Get-SmbServerConfiguration.",
            "detection_method": "None (all methods failed)",
            "confidence": "0%"
        }

    values = list(findings.values())
    detail_lines = "\n".join(f"{k.replace('_', ' ').title()} : {v}" for k, v in findings.items())

    if "Enabled" in values:
        return {
            "status": "Critical",
            "risk": "High",
            "details":
                "SMBv1 is enabled. This legacy protocol is vulnerable to attacks such as "
                "WannaCry.\n\n"
                "Detection Results\n"
                "-------------------------\n"
                f"{detail_lines}",
            "recommendation": "Disable SMBv1 immediately unless required by legacy systems.",
            "detection_method": "Windows Optional Feature + SMB Server Configuration + Registry",
            "confidence": "100%"
        }

    return {
        "status": "Passed",
        "risk": "Low",
        "details":
            "SMBv1 is disabled or not installed.\n\n"
            "Detection Results\n"
            "-------------------------\n"
            f"{detail_lines}",
        "recommendation": "No action required.",
        "detection_method": "Windows Optional Feature + SMB Server Configuration + Registry",
        "confidence": "100%"
    }
