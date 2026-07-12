from .powershell_utils import run_ps


def _run_ps(command, timeout=15):
    # Delegates to the shared, CREATE_NO_WINDOW-enabled helper
    # (see powershell_utils.py) instead of spawning its own
    # subprocess directly.
    result = run_ps(command, timeout)
    return result.stdout, result.stderr, result.returncode


def _get_autorun_value(hive):

    path = f"{hive}:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"

    script = (
        f"(Get-ItemProperty -Path '{path}' "
        "-Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
    )

    output, err, code = _run_ps(script)

    return output.strip()


def check_autorun():

    try:

        hklm_value = _get_autorun_value("HKLM")
        hkcu_value = _get_autorun_value("HKCU")

        # HKLM (machine-wide policy) takes precedence over HKCU when both
        # are set, matching how Windows itself resolves the policy.

        effective_value = hklm_value or hkcu_value
        source = "HKLM" if hklm_value else ("HKCU" if hkcu_value else None)

        # 255 (0xFF) = AutoRun disabled on all drives (recommended)
        # 0xB5 / 0x91 and similar = disabled for some but not all drive types
        if effective_value == "255":

            return {
                "status": "Passed",
                "risk": "Low",
                "details": f"AutoRun is disabled for all drives (source: {source}).",
                "recommendation": "No action required.",
                "detection_method": "Registry (HKLM + HKCU policy)",
                "confidence": "100%"
            }

        elif effective_value:

            return {
                "status": "Warning",
                "risk": "Medium",
                "details": f"AutoRun policy value is {effective_value} (source: {source}), which "
                           f"does not disable AutoRun for all drive types.",
                "recommendation": "Set NoDriveTypeAutoRun to 255 to disable AutoRun for all drives.",
                "detection_method": "Registry (HKLM + HKCU policy)",
                "confidence": "100%"
            }

        # ---------------- No explicit policy found on either hive ----------------
        # Since Windows Update KB971029 (2011), AutoRun for non-optical
        # removable media (e.g. USB drives) is disabled by default even
        # without this policy configured -- only optical/CD-style AutoPlay
        # prompts remain. Report this as the actual default rather than
        # "Unable to determine".

        return {
            "status": "Passed",
            "risk": "Low",
            "details": "No explicit AutoRun policy is configured in HKLM or HKCU. Since Windows "
                       "Update KB971029, AutoRun from removable/USB drives is disabled by "
                       "default even without this policy.",
            "recommendation": "For stricter control, explicitly set NoDriveTypeAutoRun to 255 "
                               "via Group Policy.",
            "detection_method": "Default state (no explicit policy found)",
            "confidence": "70%"
        }

    except Exception as e:

        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"AutoRun check failed: {e}",
            "recommendation": "Verify AutoRun settings manually.",
            "detection_method": "Registry",
            "confidence": "0%"
        }
