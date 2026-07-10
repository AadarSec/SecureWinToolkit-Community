"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    DNS Security
"""

from __future__ import annotations

import json
import subprocess


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

        process = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                powershell
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        if process.returncode != 0:
            raise RuntimeError(process.stderr)

        result = json.loads(process.stdout)

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

        return {
            "status": "Warning",
            "risk": "Low",
            "details": str(e),
            "recommendation": (
                "Unable to determine DNS security configuration."
            ),
            "detection_method": "PowerShell",
            "confidence": "Low",
            "data": {}
        }