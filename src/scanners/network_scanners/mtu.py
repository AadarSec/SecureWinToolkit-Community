"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    MTU
"""

from __future__ import annotations

from .helpers import get_active_network_info


def run_scan():
    """
    Retrieves the MTU configured on the active network adapter.
    """

    info = get_active_network_info()

    if info is None:

        return {
            "status": "Warning",
            "risk": "Low",
            "details": "Unable to retrieve MTU information.",
            "recommendation": (
                "Verify that the active network adapter is available."
            ),
            "detection_method": "PowerShell Get-NetIPInterface",
            "confidence": "Low",
            "data": {}
        }

    interface = info.get("InterfaceAlias", "Unknown")
    mtu = info.get("MTU")

    if mtu is None:

        return {
            "status": "Warning",
            "risk": "Low",
            "details": "Unable to determine MTU.",
            "recommendation": (
                "Verify network adapter configuration."
            ),
            "detection_method": "PowerShell Get-NetIPInterface",
            "confidence": "Low",
            "data": {}
        }

    if mtu == 1500:

        status = "Passed"
        risk = "Informational"

        recommendation = (
            "The MTU is set to the standard Ethernet value."
        )

    elif mtu > 1500:

        status = "Warning"
        risk = "Low"

        recommendation = (
            "A Jumbo Frame MTU is configured. Verify that all network devices support it."
        )

    else:

        status = "Warning"
        risk = "Low"

        recommendation = (
            "The MTU is lower than the standard Ethernet value. Verify this is intentional."
        )

    details = (
        f"Interface : {interface}\n\n"
        f"Configured MTU : {mtu}"
    )

    return {
        "status": status,
        "risk": risk,
        "details": details,
        "recommendation": recommendation,
        "detection_method": "PowerShell Get-NetIPInterface",
        "confidence": "High",
        "data": {
            "interface": interface,
            "mtu": mtu
        }
    }