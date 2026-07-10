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
