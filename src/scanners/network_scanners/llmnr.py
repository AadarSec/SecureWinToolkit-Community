"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    LLMNR Status
"""

from __future__ import annotations

import json
import subprocess


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

        return {
            "status": "Warning",
            "risk": "Low",
            "details": str(e),
            "recommendation": (
                "Unable to determine LLMNR configuration."
            ),
            "detection_method": "Windows Registry",
            "confidence": "Low",
            "data": {}
        }