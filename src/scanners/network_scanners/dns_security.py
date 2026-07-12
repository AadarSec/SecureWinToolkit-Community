"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    DNS Security
"""

from __future__ import annotations

from .helpers import build_error_result, run_powershell


def run_scan():
    """
    Audits DNS security configuration.
    Checks whether DNS-over-HTTPS (DoH) is enabled.
    """

    powershell = r"""
try
{
    $settings = Get-DnsClientDohServerAddress -ErrorAction Stop

    if($settings)
    {
        $enabled = $true
    }
    else
    {
        $enabled = $false
    }
}
catch
{
    $enabled = $false
}

$result = @{
    DoHEnabled = $enabled
}

$result | ConvertTo-Json
"""

    try:

        result = run_powershell(powershell)

        doh = result.get("DoHEnabled", False)

        if doh:

            status = "Passed"
            risk = "Low"

            details = (
                "Encrypted DNS (DNS over HTTPS) is configured."
            )

            recommendation = (
                "No action required."
            )

        else:

            status = "Information"
            risk = "Informational"

            details = (
                "Encrypted DNS (DNS over HTTPS) is not configured."
            )

            recommendation = (
                "Consider enabling DNS over HTTPS (DoH) "
                "to protect DNS queries from interception."
            )

        return {
            "status": status,
            "risk": risk,
            "details": details,
            "recommendation": recommendation,
            "detection_method": (
                "PowerShell Get-DnsClientDohServerAddress"
            ),
            "confidence": "High",
            "data": result
        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to determine DNS security configuration.",
            "PowerShell",
        )
