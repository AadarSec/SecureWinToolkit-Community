from src.scanners.windows_defender import check_windows_defender
from src.scanners.firewall import check_firewall
from src.scanners.bitlocker import check_bitlocker
from src.scanners.secure_boot import check_secure_boot
from src.scanners.tpm import check_tpm
from src.scanners.smartscreen import check_smartscreen
from src.scanners.uac import check_uac
from src.scanners.windows_update import check_windows_update


def run_windows_audit():

    results = {}

    results["Windows Defender"] = check_windows_defender()

    results["Firewall"] = check_firewall()

    results["BitLocker"] = check_bitlocker()

    results["Secure Boot"] = check_secure_boot()

    results["TPM"] = check_tpm()

    results["SmartScreen"] = check_smartscreen()

    results["User Account Control"] = check_uac()

    results["Windows Update"] = check_windows_update()

    return results
