"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    NetBIOS Status
"""

from __future__ import annotations

import json
import subprocess


def run_scan():
    """
    Checks whether NetBIOS over TCP/IP is enabled
    on the active network adapter.
    """

    powershell = r"""
$adapter = Get-CimInstance Win32_NetworkAdapterConfiguration |
Where-Object {
    $_.IPEnabled -eq $true
} |
Select-Object -First 1

if ($null -eq $adapter)
{
    exit 1
}

switch ($adapter.TcpipNetbiosOptions)
{
    0 { $status = "Default" }
    1 { $status = "Enabled" }
    2 { $status = "Disabled" }
    Default { $status = "Unknown" }
}

$result = @{
    Description = $adapter.Description
    NetBIOS = $status
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

        adapter = result.get("Description", "Unknown")
        status_value = result.get("NetBIOS", "Unknown")

        if status_value == "Disabled":

            status = "Passed"
            risk = "Low"

            recommendation = (
                "NetBIOS over TCP/IP is disabled. "
                "No action is required."
            )

        elif status_value == "Enabled":

            status = "Warning"
            risk = "Medium"

            recommendation = (
                "Disable NetBIOS over TCP/IP unless it is required by "
                "legacy applications."
            )

        else:

            status = "Information"
            risk = "Informational"

            recommendation = (
                "NetBIOS is using the default DHCP-controlled setting. "
                "Verify your organization's policy."
            )

        details = (
            f"Adapter : {adapter}\n\n"
            f"NetBIOS Status : {status_value}"
        )

        return {
            "status": status,
            "risk": risk,
            "details": details,
            "recommendation": recommendation,
            "detection_method": (
                "WMI Win32_NetworkAdapterConfiguration"
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
                "Unable to determine NetBIOS configuration."
            ),
            "detection_method": "WMI",
            "confidence": "Low",
            "data": {}
        }