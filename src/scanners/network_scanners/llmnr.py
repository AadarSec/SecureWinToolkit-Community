"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    LLMNR Status
"""

from __future__ import annotations

from .helpers import build_error_result, run_powershell


def run_scan():
    """
    Checks whether LLMNR is enabled or disabled.
    """

    powershell = r"""
try
{
    $value = Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name EnableMulticast `
        -ErrorAction Stop

    $enabled = ($value.EnableMulticast -eq 1)
}
catch
{
    # Registry value not configured.
    # Windows defaults to LLMNR enabled.
    $enabled = $true
}

$result = @{
    LLMNR = $enabled
}

$result | ConvertTo-Json
"""

    try:

        result = run_powershell(powershell)

        enabled = result.get("LLMNR", True)

        if enabled:

            status = "Warning"
            risk = "Medium"

            details = (
                "LLMNR is enabled.\n\n"
                "This system may respond to multicast name resolution requests."
            )

            recommendation = (
                "Disable LLMNR using Group Policy or the registry to reduce "
                "the risk of name resolution poisoning attacks."
            )

        else:

            status = "Passed"
            risk = "Low"

            details = (
                "LLMNR is disabled.\n\n"
                "The system is protected against LLMNR-based name resolution attacks."
            )

            recommendation = (
                "No action required."
            )

        return {
            "status": status,
            "risk": risk,
            "details": details,
            "recommendation": recommendation,
            "detection_method": (
                "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
            ),
            "confidence": "High",
            "data": result
        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to determine LLMNR configuration.",
            "Windows Registry",
        )
