"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    IPv6 Status
"""

from __future__ import annotations

from .helpers import get_active_network_info


def run_scan():
    """
    Retrieves IPv6 configuration of the active network adapter.
    """

    info = get_active_network_info()

    if info is None:

        return {
            "status": "Warning",
            "risk": "Low",
            "details": "Unable to retrieve active network information.",
            "recommendation": (
                "Verify that a network adapter is connected."
            ),
            "detection_method": "PowerShell Get-NetIPConfiguration",
            "confidence": "Low",
            "data": {}
        }

    interface = info.get("InterfaceAlias", "Unknown")
    ipv6 = info.get("IPv6")

    if ipv6:

        status = "Passed"
        risk = "Informational"

        details = (
            f"Interface : {interface}\n\n"
            f"IPv6 Address : {ipv6}"
        )

        recommendation = (
            "Verify that IPv6 is required and properly secured "
            "within your environment."
        )

    else:

        status = "Warning"
        risk = "Low"

        details = (
            f"Interface : {interface}\n\n"
            "IPv6 is not configured on the active adapter."
        )

        recommendation = (
            "If your environment requires IPv6, enable and configure it. "
            "Otherwise this may be acceptable."
        )

    return {
        "status": status,
        "risk": risk,
        "details": details,
        "recommendation": recommendation,
        "detection_method": "PowerShell Get-NetIPConfiguration",
        "confidence": "High",
        "data": {
            "interface": interface,
            "ipv6": ipv6
        }
    }