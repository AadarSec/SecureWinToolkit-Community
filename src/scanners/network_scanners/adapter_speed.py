"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Adapter Speed
"""

from __future__ import annotations

from .helpers import get_active_network_info


def run_scan():
    """
    Retrieves active network adapter speed.
    """

    info = get_active_network_info()

    if info is None:

        return {
            "status": "Warning",
            "risk": "Low",
            "details": "Unable to retrieve adapter information.",
            "recommendation": (
                "Verify that a network adapter is connected."
            ),
            "detection_method": "PowerShell Get-NetAdapter",
            "confidence": "Low",
            "data": {}
        }

    interface = info.get("InterfaceAlias", "Unknown")
    speed = info.get("LinkSpeed", "Unknown")
    media = info.get("MediaType", "Unknown")
    status = info.get("Status", "Unknown")

    if status.lower() == "up":

        scan_status = "Passed"
        risk = "Informational"

    else:

        scan_status = "Warning"
        risk = "Low"

    details = (
        f"Interface : {interface}\n\n"
        f"Link Speed : {speed}\n\n"
        f"Media Type : {media}\n\n"
        f"Adapter Status : {status}"
    )

    return {
        "status": scan_status,
        "risk": risk,
        "details": details,
        "recommendation": (
            "Verify that the negotiated link speed matches the expected "
            "network infrastructure."
        ),
        "detection_method": "PowerShell Get-NetAdapter",
        "confidence": "High",
        "data": {
            "interface": interface,
            "link_speed": speed,
            "media_type": media,
            "adapter_status": status
        }
    }