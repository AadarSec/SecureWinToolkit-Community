"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Network Isolation
"""

from __future__ import annotations

import json
import subprocess


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

        return {
            "status": "Warning",
            "risk": "Low",
            "details": str(e),
            "recommendation": (
                "Unable to determine network isolation status."
            ),
            "detection_method": "PowerShell",
            "confidence": "Low",
            "data": {}
        }