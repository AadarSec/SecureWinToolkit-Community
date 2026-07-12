"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Wi-Fi Encryption
"""

from __future__ import annotations

from .helpers import build_error_result, get_wlan_interface_info


def run_scan():

    try:

        info = get_wlan_interface_info()

        if info is None:

            return {
                "status": "Information",
                "risk": "Informational",
                "details": "No wireless adapter is currently connected.",
                "recommendation": (
                    "Connect to a wireless network to evaluate "
                    "wireless security."
                ),
                "detection_method": "netsh wlan show interfaces",
                "confidence": "High",
                "data": {}
            }

        auth = info.get("Authentication", "Unknown")
        cipher = info.get("Cipher", "Unknown")

        auth_upper = auth.upper()

        status = "Passed"
        risk = "Low"
        security_rating = "Excellent"

        recommendation = (
            "The current wireless connection meets modern security best practices."
        )

        if "OPEN" in auth_upper:

            status = "Critical"
            risk = "High"
            security_rating = "Unsecured"

            recommendation = (
                "Avoid connecting to open wireless networks because "
                "traffic can be intercepted."
            )

        elif "WEP" in auth_upper:

            status = "Critical"
            risk = "High"
            security_rating = "Obsolete"

            recommendation = (
                "Replace WEP with WPA2 or WPA3 immediately."
            )

        elif (
            "WPA" in auth_upper
            and "WPA2" not in auth_upper
            and "WPA3" not in auth_upper
        ):

            status = "Warning"
            risk = "Medium"
            security_rating = "Weak"

            recommendation = (
                "Upgrade the wireless network to WPA2 or WPA3."
            )

        elif "WPA2" in auth_upper:

            security_rating = "Good"

            recommendation = (
                "The connection uses WPA2 encryption. "
                "Consider upgrading to WPA3 if available."
            )

        elif "WPA3" in auth_upper:

            security_rating = "Excellent"

            recommendation = (
                "The connection uses WPA3 encryption and follows "
                "current wireless security recommendations."
            )

        details = (
            f"Authentication : {auth}\n\n"
            f"Encryption : {cipher}\n\n"
            f"Security Rating : {security_rating}"
        )

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": recommendation,

            "detection_method": "netsh wlan show interfaces",

            "confidence": "High",

            "data": {

                "authentication": auth,
                "cipher": cipher,
                "security_rating": security_rating

            }

        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to determine wireless security configuration.",
            "netsh",
        )
