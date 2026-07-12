"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Network Profile
"""

from __future__ import annotations

from .helpers import build_error_result, get_active_network_info


def run_scan():
    """
    Retrieves the active Windows network profile.
    """

    info = get_active_network_info()

    if info is None:

        return build_error_result(
            "Unable to retrieve network profile.",
            "Verify that an active network adapter is connected.",
            "PowerShell Get-NetConnectionProfile",
        )

    interface = info.get("InterfaceAlias", "Unknown")
    profile = info.get("NetworkCategory", "Unknown")

    if profile == "Private":

        status = "Passed"
        risk = "Informational"

        recommendation = (
            "The active network is configured as a Private network. "
            "Verify that this is appropriate for your environment."
        )

    elif profile == "Public":

        status = "Passed"
        risk = "Informational"

        recommendation = (
            "The active network is configured as a Public network. "
            "This is recommended for untrusted networks."
        )

    elif profile == "Domain":

        status = "Passed"
        risk = "Informational"

        recommendation = (
            "The active network is domain authenticated."
        )

    else:

        status = "Warning"
        risk = "Low"

        recommendation = (
            "Unable to determine the current network profile."
        )

    details = (
        f"Interface : {interface}\n\n"
        f"Network Profile : {profile}"
    )

    return {
        "status": status,
        "risk": risk,
        "details": details,
        "recommendation": recommendation,
        "detection_method": "PowerShell Get-NetConnectionProfile",
        "confidence": "High",
        "data": {
            "interface": interface,
            "network_profile": profile
        }
    }
