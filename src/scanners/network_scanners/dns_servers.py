"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    DNS Servers
"""

from __future__ import annotations

from .helpers import get_active_network_info


def run_scan():
    """
    Retrieves DNS servers configured on the active network adapter.
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

    dns_servers = info.get("DNSServers")

    if not dns_servers:
        return {
            "status": "Warning",
            "risk": "Low",
            "details": "No DNS servers were detected.",
            "recommendation": (
                "Verify your DNS configuration."
            ),
            "detection_method": "PowerShell Get-NetIPConfiguration",
            "confidence": "Medium",
            "data": {}
        }

    if isinstance(dns_servers, str):
        dns_servers = [dns_servers]

    details = "Configured DNS Servers:\n\n"

    for dns in dns_servers:
        details += f"• {dns}\n"

    return {
        "status": "Passed",
        "risk": "Informational",
        "details": details.strip(),
        "recommendation": (
            "Verify these DNS servers belong to your trusted network."
        ),
        "detection_method": "PowerShell Get-NetIPConfiguration",
        "confidence": "High",
        "data": {
            "dns_servers": dns_servers
        }
    }