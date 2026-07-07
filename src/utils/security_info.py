"""
Security status checks: Windows Defender, Firewall, BitLocker.

Design goal: stay FAST. We avoid spawning PowerShell (slow startup,
~300-800ms per call) wherever a registry read gets us the same answer.
BitLocker has no reliable registry-only signal, so it uses `manage-bde`
(a native exe, much faster than powershell.exe) with a safe fallback.
"""

import subprocess
import winreg


def _read_reg(hive, path, name, default=None):
    try:
        key = winreg.OpenKey(hive, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except Exception:
        return default


# ---- Raw status checks (internal states, unchanged for logic) ----

def get_defender_status():
    """Returns 'Enabled', 'Disabled', or 'Unknown'."""
    value = _read_reg(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
        default=None,
    )
    if value is None:
        return "Enabled"
    return "Disabled" if int(value) == 1 else "Enabled"


def get_firewall_status():
    """Returns 'Enabled', 'Disabled', 'Partial', or 'Unknown'."""
    profiles = ["DomainProfile", "StandardProfile", "PublicProfile"]
    base_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

    states = []
    for profile in profiles:
        value = _read_reg(
            winreg.HKEY_LOCAL_MACHINE,
            f"{base_path}\\{profile}",
            "EnableFirewall",
            default=None,
        )
        if value is not None:
            states.append(int(value))

    if not states:
        return "Unknown"
    if all(s == 1 for s in states):
        return "Enabled"
    if all(s == 0 for s in states):
        return "Disabled"
    return "Partial"


def get_bitlocker_status(drive="C:"):
    """Returns 'Protected', 'Unprotected', or 'Unknown'."""
    try:
        result = subprocess.check_output(
            ["manage-bde", "-status", drive],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=5,
        )
        if "Protection On" in result:
            return "Protected"
        if "Protection Off" in result:
            return "Unprotected"
        return "Unknown"
    except Exception:
        return "Unknown"


# ---- Display label mappings (final-polish renames) ----

DEFENDER_LABELS = {
    "Enabled": "Protected",
    "Disabled": "Disabled",
    "Unknown": "Unknown",
}

FIREWALL_LABELS = {
    "Enabled": "Enabled",
    "Disabled": "Disabled",
    "Partial": "Partially Enabled",
    "Unknown": "Unknown",
}

BITLOCKER_LABELS = {
    "Protected": "Protected",
    "Unprotected": "Unprotected",
    "Unknown": "Not Configured",
}


def calculate_security_score(defender, firewall, bitlocker):
    """
    Weighted score out of 100:
      Defender  -> 40 pts
      Firewall  -> 35 pts
      BitLocker -> 25 pts
    """
    score = 0

    if defender == "Enabled":
        score += 40
    elif defender == "Unknown":
        score += 20

    if firewall == "Enabled":
        score += 35
    elif firewall in ("Partial", "Unknown"):
        score += 18

    if bitlocker == "Protected":
        score += 25
    elif bitlocker == "Unknown":
        score += 12

    return score


def get_check_summary(defender, firewall, bitlocker):
    """
    Returns (passed, warnings, critical) counts across the 3 checks.
    """
    passed = warnings = critical = 0

    # Defender
    if defender == "Enabled":
        passed += 1
    elif defender == "Unknown":
        warnings += 1
    else:
        critical += 1

    # Firewall
    if firewall == "Enabled":
        passed += 1
    elif firewall in ("Partial", "Unknown"):
        warnings += 1
    else:
        critical += 1

    # BitLocker
    if bitlocker == "Protected":
        passed += 1
    elif bitlocker == "Unknown":
        warnings += 1
    else:
        critical += 1

    return passed, warnings, critical


def get_security_info():
    defender = get_defender_status()
    firewall = get_firewall_status()
    bitlocker = get_bitlocker_status()

    score = calculate_security_score(defender, firewall, bitlocker)
    passed, warnings, critical = get_check_summary(defender, firewall, bitlocker)

    return {
        "Defender": defender,
        "Defender Label": DEFENDER_LABELS.get(defender, defender),
        "Firewall": firewall,
        "Firewall Label": FIREWALL_LABELS.get(firewall, firewall),
        "BitLocker": bitlocker,
        "BitLocker Label": BITLOCKER_LABELS.get(bitlocker, bitlocker),
        "Security Score": score,
        "Passed": passed,
        "Warnings": warnings,
        "Critical": critical,
    }


if __name__ == "__main__":
    import time
    t0 = time.perf_counter()
    info = get_security_info()
    elapsed = time.perf_counter() - t0

    for k, v in info.items():
        print(f"{k}: {v}")
    print(f"\n(gathered in {elapsed*1000:.1f} ms)")
