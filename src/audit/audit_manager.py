from src.scanners.windows_defender import check_windows_defender
from src.scanners.firewall import check_firewall
from src.scanners.bitlocker import check_bitlocker
from src.scanners.secure_boot import check_secure_boot
from src.scanners.tpm import check_tpm
from src.scanners.smartscreen import check_smartscreen
from src.scanners.uac import check_uac
from src.scanners.windows_update import check_windows_update


# =====================================================
# SCANNER REGISTRY
# =====================================================
# Each scanner carries its own metadata. This is the single
# source of truth for which checks exist, whether they need
# admin rights, and which function implements them.
#
# Future metadata (not used yet, but the shape is ready for it):
#   "estimated_time": 2,
#   "category": "Core Security",
#   "requires_reboot": False,
#   "premium": False,
#   "os": ["Windows 10", "Windows 11"]
# =====================================================

SCANNERS = {

    "Windows Defender": {
        "admin": False,
        "function": check_windows_defender
    },

    "Firewall": {
        "admin": False,
        "function": check_firewall
    },

    "BitLocker": {
        "admin": True,
        "function": check_bitlocker
    },

    "Secure Boot": {
        "admin": True,
        "function": check_secure_boot
    },

    "TPM": {
        "admin": True,
        "function": check_tpm
    },

    "SmartScreen": {
        "admin": True,
        "function": check_smartscreen
    },

    "User Account Control": {
        "admin": False,
        "function": check_uac
    },

    "Windows Update": {
        "admin": False,
        "function": check_windows_update
    },

}


def run_windows_audit(selected=None):
    """
    Runs the Windows security audit.

    selected : optional list of check names (must match keys in
               SCANNERS) to run. If None, all checks run.
    """

    if selected is None:
        selected = list(SCANNERS.keys())

    results = {}

    for name in selected:

        scanner = SCANNERS.get(name)

        if scanner is None:
            continue

        results[name] = scanner["function"]()

    return results


def needs_admin(selected):
    """
    Returns True if any of the selected check names require
    Administrator rights to return accurate results.
    """

    return any(
        SCANNERS.get(name, {}).get("admin", False)
        for name in selected
    )


def get_admin_required_names(selected):
    """
    Returns the list of selected check names that specifically
    require Administrator rights (useful for showing a precise
    message to the user, e.g. "BitLocker, TPM need admin rights").
    """

    return [
        name for name in selected
        if SCANNERS.get(name, {}).get("admin", False)
    ]
