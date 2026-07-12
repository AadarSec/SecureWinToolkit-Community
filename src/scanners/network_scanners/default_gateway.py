"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Default Gateway
"""

from __future__ import annotations

from .helpers import build_error_result, get_active_network_info


def run_scan():
    """
    Retrieves the active network adapter's default gateway.
    """

    info = get_active_network_info()

    if info is None:
        return build_error_result(
            "Unable to retrieve active network information.",
            "Verify that an active network adapter is connected.",
            "PowerShell Get-NetIPConfiguration",
        )

    gateway = info.get("Gateway")

    if gateway:

        return {
            "status": "Passed",
            "risk": "Informational",
            "details": f"Default Gateway : {gateway}",
            "recommendation": (
                "Verify that this gateway belongs to your trusted network."
            ),
            "detection_method": "PowerShell Get-NetIPConfiguration",
            "confidence": "High",
            "data": {
                "gateway": gateway
            }
        }

    return {
        "status": "Warning",
        "risk": "Low",
        "details": "No default gateway was detected.",
        "recommendation": (
            "Check your network adapter configuration."
        ),
        "detection_method": "PowerShell Get-NetIPConfiguration",
        "confidence": "Medium",
        "data": {}
    }
