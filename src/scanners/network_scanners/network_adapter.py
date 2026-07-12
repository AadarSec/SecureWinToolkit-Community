"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Network Adapter
"""

from __future__ import annotations

from .helpers import build_error_result, get_active_network_info


def run_scan():
    """
    Retrieves information about the active network adapter.
    """

    info = get_active_network_info()

    if info is None:

        return build_error_result(
            "Unable to retrieve active network adapter.",
            "Verify that a network adapter is connected and enabled.",
            "PowerShell Get-NetIPConfiguration",
        )

    interface = info.get("InterfaceAlias", "Unknown")
    description = info.get("InterfaceDescription", "Unknown")
    ipv4 = info.get("IPv4", "Not Assigned")

    # Detect adapter type
    interface_lower = interface.lower()

    if "wi-fi" in interface_lower or "wireless" in interface_lower:

        adapter_type = "Wireless"

    elif "ethernet" in interface_lower:

        adapter_type = "Ethernet"

    else:

        adapter_type = "Unknown"

    details = (
        f"Interface Alias : {interface}\n\n"
        f"Description : {description}\n\n"
        f"Connection Type : {adapter_type}\n\n"
        f"IPv4 Address : {ipv4}"
    )

    return {
        "status": "Passed",
        "risk": "Informational",
        "details": details,
        "recommendation": (
            "Verify that the active adapter matches the expected network connection."
        ),
        "detection_method": "PowerShell Get-NetIPConfiguration",
        "confidence": "High",
        "data": {
            "interface": interface,
            "description": description,
            "adapter_type": adapter_type,
            "ipv4": ipv4
        }
    }
