import subprocess

def _run_ps(command: str) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return r.stdout.strip()
    except Exception:
        return ""

def defender_enabled():
    return _run_ps("(Get-MpComputerStatus).AntivirusEnabled").lower() == "true"

def firewall_enabled():
    out = _run_ps("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}).Count")
    try:
        return int(out) == 3
    except Exception:
        return False

def bitlocker_enabled():
    return _run_ps("(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus") == "1"

def secure_boot_enabled():
    return _run_ps("Confirm-SecureBootUEFI").lower() == "true"

def calculate_security_score():
    score = 0
    if defender_enabled():
        score += 30
    if firewall_enabled():
        score += 25
    if bitlocker_enabled():
        score += 25
    if secure_boot_enabled():
        score += 20

    if score >= 85:
        health = "Healthy"
    elif score >= 60:
        health = "Warning"
    else:
        health = "Critical"

    return {
        "score": score,
        "health": health,
        "defender": defender_enabled(),
        "firewall": firewall_enabled(),
        "bitlocker": bitlocker_enabled(),
        "secure_boot": secure_boot_enabled(),
    }
