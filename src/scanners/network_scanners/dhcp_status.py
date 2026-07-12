"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    DHCP Status
"""

from __future__ import annotations

from .helpers import build_error_result, get_active_network_info


def run_scan():
    """
    Retrieves DHCP status of the active network adapter.
    """

    info = get_active_network_info()

    if info is None:
        return build_error_result(
            "Unable to retrieve active network information.",
            "Verify that an active network adapter is connected.",
            "PowerShell Get-NetIPConfiguration",
        )

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
