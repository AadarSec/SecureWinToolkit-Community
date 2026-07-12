"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Network Isolation
"""

from __future__ import annotations

from .helpers import build_error_result, run_powershell


def run_scan():
    """
    Evaluates the system's network exposure by checking:

    • Network Discovery
    • File & Printer Sharing
    """

    powershell = r"""
$networkDiscovery = Get-NetFirewallRule `
    -DisplayGroup "Network Discovery" |
    Where-Object {$_.Enabled -eq "True"}

$fileSharing = Get-NetFirewallRule `
    -DisplayGroup "File And Printer Sharing" |
    Where-Object {$_.Enabled -eq "True"}

$result = @{
    NetworkDiscovery = ($networkDiscovery.Count -gt 0)
    FileSharing = ($fileSharing.Count -gt 0)
}

$result | ConvertTo-Json
"""

    try:

        result = run_powershell(powershell)

        discovery = result.get("NetworkDiscovery", False)
        sharing = result.get("FileSharing", False)

        findings = []

        if discovery:
            findings.append("Network Discovery is enabled.")

        if sharing:
            findings.append("File & Printer Sharing is enabled.")

        if not findings:

            status = "Passed"
            risk = "Low"

            details = (
                "Network Discovery is disabled.\n\n"
                "File & Printer Sharing is disabled."
            )

            recommendation = (
                "The system has a reduced network exposure."
            )

        else:

            status = "Warning"
            risk = "Medium"

            details = "\n".join(f"• {item}" for item in findings)

            recommendation = (
                "Disable Network Discovery and File & Printer Sharing "
                "on untrusted networks."
            )

        return {
            "status": status,
            "risk": risk,
            "details": details,
            "recommendation": recommendation,
            "detection_method": (
                "PowerShell Get-NetFirewallRule"
            ),
            "confidence": "High",
            "data": result
        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to determine network isolation status.",
            "PowerShell",
        )
