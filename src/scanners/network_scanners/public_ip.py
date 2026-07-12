"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Public IP Address
"""

from __future__ import annotations

from .helpers import build_error_result, get_public_ip


def run_scan():
    """
    Execute Public IP scanner.
    """

    result = get_public_ip()

    if result:

        return {
            "status": "Passed",
            "risk": "Informational",
            "details": f"Public IP Address : {result}",
            "recommendation": (
                "Verify that this public IP belongs to your expected "
                "internet connection."
            ),
            "detection_method": "HTTPS Public IP Lookup",
            "confidence": "High",
            "data": {
                "public_ip": result
            }
        }

    return build_error_result(
        "Unable to retrieve Public IP.",
        "Check your internet connectivity.",
        "HTTPS Public IP Lookup",
    )
