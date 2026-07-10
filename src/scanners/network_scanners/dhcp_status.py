"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    DHCP Status
"""

from __future__ import annotations

from .helpers import get_active_network_info


def run_scan():
    """
    Retrieves DHCP status of the active network adapter.
    """

    info = get_active_network_info()

    if info is None:
        return {
            "status": "Warning",
            "risk": "Low",
            "details": "Unable to retrieve active network information.",
            "recommendation": (
                "Verify that an active network adapter is connected."
            ),
            "detection_method": "PowerShell Get-NetIPConfiguration",
            "confidence": "Low",
            "data": {}
        }

    dhcp = info.get("DHCP", "Unknown")

    if dhcp == "Enabled":

        status = "Passed"
        risk = "Informational"
        confidence = "High"

    elif dhcp == "Disabled":

        status = "Warning"
        risk = "Low"
        confidence = "High"

    else:

        status = "Warning"
        risk = "Unknown"
        confidence = "Low"

    return {
        "status": status,
        "risk": risk,
        "details": f"DHCP Status : {dhcp}",
        "recommendation": (
            "Verify the DHCP configuration matches your network requirements."
        ),
        "detection_method": "PowerShell Get-NetIPInterface",
        "confidence": confidence,
        "data": {
            "dhcp_status": dhcp
        }
    }