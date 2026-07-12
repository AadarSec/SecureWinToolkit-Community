from concurrent.futures import ThreadPoolExecutor, as_completed

from .administrator_account import check_administrator_account
from .autorun import check_autorun
from .bitlocker import check_bitlocker
from .credential_guard import check_credential_guard
from .file_printer_sharing import check_file_printer_sharing
from .firewall import check_firewall
from .guest_account import check_guest_account
from .network_discovery import check_network_discovery
from .password_policy import check_password_policy
from .print_spooler import check_print_spooler
from .rdp import check_rdp
from .remote_assistance import check_remote_assistance
from .remote_registry import check_remote_registry
from .secure_boot import check_secure_boot
from .smartscreen import check_smartscreen
from .smbv1 import check_smbv1
from .snmp import check_snmp
from .telnet import check_telnet
from .tpm import check_tpm
from .uac import check_uac
from .windows_defender import check_windows_defender
from .windows_event_log import check_windows_event_log
from .windows_update import check_windows_update
from .winrm import check_winrm


# =====================================================
# SCANNER MAP
# Maps the exact check name shown in the GUI (as used in
# WindowsAudit.CATEGORIES) to the scanner function that
# implements it.
# =====================================================

# NOTE: these keys MUST exactly match the scanner names used in
# src/core/scanner_metadata.py (SCANNER_METADATA). The GUI (WindowsAudit)
# builds its category list from that metadata now, so the names here
# are no longer free-form -- they are looked up directly by name.
SCANNER_MAP = {
    "Administrator Account": check_administrator_account,
    "Guest Account": check_guest_account,
    "Password Policy": check_password_policy,

    "UAC": check_uac,
    "BitLocker": check_bitlocker,
    "Secure Boot": check_secure_boot,
    "TPM": check_tpm,
    "Credential Guard": check_credential_guard,
    "SmartScreen": check_smartscreen,
    "Windows Defender": check_windows_defender,

    "Windows Update": check_windows_update,

    "Windows Firewall": check_firewall,
    "Network Discovery": check_network_discovery,
    "File & Printer Sharing": check_file_printer_sharing,
    "SMBv1": check_smbv1,

    "Remote Desktop": check_rdp,
    "Remote Assistance": check_remote_assistance,
    "Remote Registry": check_remote_registry,
    "WinRM": check_winrm,

    "Print Spooler": check_print_spooler,
    "SNMP": check_snmp,
    "Telnet": check_telnet,
    "AutoRun": check_autorun,
    "Windows Event Log": check_windows_event_log,
}


# =====================================================
# PARALLEL SCANNER RUNNER
# =====================================================
# Every scanner in SCANNER_MAP does I/O (spawns a PowerShell/CIM/registry
# call and waits on it) -- it is not CPU-bound. That means the previous
# sequential "run one, wait, run the next" loop in the GUI was leaving
# almost all of the wall-clock time on the table: while one scanner's
# subprocess is blocked waiting on Windows to answer, the CPU is idle and
# could be running the next scanner's subprocess at the same time.
#
# run_scanners_parallel() runs the requested checks concurrently using a
# thread pool (threads are fine here since each scanner just blocks on
# subprocess.run / winreg, releasing the GIL) and reports progress via a
# callback as each result comes in, so a GUI can still update a progress
# bar incrementally instead of freezing until everything finishes.
#
# Typical effect: a full run of ~24 scanners that used to take the sum of
# every scanner's PowerShell startup + execution time now takes roughly
# the time of the *slowest* scanner (plus a small amount of thread-pool
# scheduling overhead), since most of it happens side-by-side.
def run_scanners_parallel(scanner_names, on_result=None, max_workers=8):
    """
    Run the given scanner names concurrently.

    Args:
        scanner_names: iterable of keys into SCANNER_MAP.
        on_result: optional callback(name, result, completed, total),
            invoked from a worker thread as each scan completes. If you're
            updating GUI widgets from this callback, marshal it back onto
            the main/UI thread (e.g. via `after()` in tkinter) -- this
            function itself does not touch any UI state.
        max_workers: size of the thread pool. Scanners are I/O-bound, so
            this can safely exceed the CPU core count; 8 is a reasonable
            default that avoids overwhelming WMI/PowerShell if the user
            selects every check at once.

    Returns:
        dict mapping scanner name -> result dict, in the same shape each
        individual scan_function() already returns.
    """

    scanner_names = list(scanner_names)
    total = len(scanner_names)
    results = {}

    def _run_one(name):
        scan_function = SCANNER_MAP.get(name)
        if scan_function is None:
            return name, {
                "status": "Warning",
                "risk": "Unknown",
                "details": f"No scanner is registered for '{name}'.",
                "recommendation": "Verify this check manually.",
                "detection_method": "None",
                "confidence": "0%"
            }
        try:
            return name, scan_function()
        except Exception as e:
            return name, {
                "status": "Warning",
                "risk": "Unknown",
                "details": f"'{name}' scan failed unexpectedly: {e}",
                "recommendation": "Verify this check manually.",
                "detection_method": "None",
                "confidence": "0%"
            }

    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, name): name for name in scanner_names}

        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result
            completed += 1

            if on_result is not None:
                on_result(name, result, completed, total)

    return results
