from src.scanners.windows_defender import check_windows_defender
from src.scanners.firewall import check_firewall
from src.scanners.bitlocker import check_bitlocker
from src.scanners.secure_boot import check_secure_boot
from src.scanners.tpm import check_tpm
from src.scanners.smartscreen import check_smartscreen
from src.scanners.uac import check_uac
from src.scanners.windows_update import check_windows_update
from src.scanners.rdp import check_rdp
from src.scanners.smbv1 import check_smbv1
from src.scanners.remote_registry import check_remote_registry
from src.scanners.winrm import check_winrm
from src.scanners.guest_account import check_guest_account
from src.scanners.administrator_account import check_administrator_account
from src.scanners.network_discovery import check_network_discovery
from src.scanners.file_printer_sharing import check_file_printer_sharing
from src.scanners.remote_assistance import check_remote_assistance
from src.scanners.autorun import check_autorun
from src.scanners.password_policy import check_password_policy
from src.scanners.print_spooler import check_print_spooler
from src.scanners.snmp import check_snmp
from src.scanners.telnet import check_telnet
from src.scanners.windows_event_log import check_windows_event_log
from src.scanners.credential_guard import check_credential_guard


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
    "Remote Desktop": {
        "admin": False,
        "function": check_rdp
    },
    "SMBv1": {
        "admin": True,
        "function": check_smbv1
    },
    "Remote Registry": {
        "admin": False,
        "function": check_remote_registry
    },
    "WinRM": {
        "admin": False,
        "function": check_winrm
    },
    "Network Discovery": {
         "admin": False,
        "function": check_network_discovery
    },

    "File & Printer Sharing": {
        "admin": False,
        "function": check_file_printer_sharing
    },

    "Remote Assistance": {
        "admin": False,
        "function": check_remote_assistance
    },

    "AutoRun / AutoPlay": {
        "admin": False,
        "function": check_autorun
    },

    "Guest Account": {
        "admin": False,
        "function": check_guest_account
    },
    "Administrator Account": {
        "admin": False,
        "function": check_administrator_account
    },
    "Password Policy": {
        "admin": False,
        "function": check_password_policy
    },
    "Print Spooler": {
        "admin": False,
        "function": check_print_spooler
    },
    "SNMP": {
        "admin": False,
        "function": check_snmp
    },
    "Telnet": {
        "admin": False,
        "function": check_telnet
    },
    "Windows Event Log": {
        "admin": False,
        "function": check_windows_event_log
    },
    "Credential Guard": {
        "admin": True,
        "function": check_credential_guard
    },
}
def run_windows_audit(selected=None, progress_callback=None):
    """
    Runs the Windows security audit.

    selected : optional list of scanner names.

    progress_callback(current, total, scanner_name, result)
    """

    if selected is None:
        selected = list(SCANNERS.keys())

    results = {}

    total = len(selected)

    for current, name in enumerate(selected, start=1):

        scanner = SCANNERS.get(name)

        if scanner is None:
            continue

        result = scanner["function"]()

        results[name] = result

        if progress_callback is not None:

            progress_callback(
                current=current,
                total=total,
                scanner_name=name,
                result=result
            )

    return results

def run_windows_audit(selected=None, progress_callback=None):
    """
    Runs the Windows security audit.

    selected : optional list of scanner names.

    progress_callback(current, total, scanner_name, result)
    """

    if selected is None:
        selected = list(SCANNERS.keys())

    results = {}

    total = len(selected)

    for current, name in enumerate(selected, start=1):

        scanner = SCANNERS.get(name)

        if scanner is None:
            continue

        result = scanner["function"]()

        results[name] = result

        if progress_callback is not None:

            progress_callback(
                current=current,
                total=total,
                scanner_name=name,
                result=result
            )

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
