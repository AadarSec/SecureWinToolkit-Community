"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    MAC Address
"""

from __future__ import annotations

from .helpers import get_active_network_info


def run_scan():
    """
    Retrieves MAC address of the active network adapter.
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
            "detection_method": "PowerShell Get-NetAdapter",
            "confidence": "Low",
            "data": {}
        }

    interface = info.get("InterfaceAlias", "Unknown")
    mac = info.get("MACAddress")

    if mac:

        mac = mac.replace("-", ":")

        return {
            "status": "Passed",
            "risk": "Informational",
            "details": (
                f"Active Adapter : {interface}\n"
                f"MAC Address : {mac}"
            ),
            "recommendation": (
                "Verify that this MAC address belongs to the expected network adapter."
            ),
            "detection_method": "PowerShell Get-NetAdapter",
            "confidence": "High",
            "data": {
                "interface": interface,
                "mac_address": mac
            }
        }

    return {
        "status": "Warning",
        "risk": "Low",
        "details": "Unable to retrieve MAC address.",
        "recommendation": (
            "Verify that the network adapter is enabled."
        ),
        "detection_method": "PowerShell Get-NetAdapter",
        "confidence": "Medium",
        "data": {}
    }