"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Wi-Fi Encryption
"""

from __future__ import annotations

import subprocess


def run_scan():

    try:

        result = subprocess.run(
            [
                "netsh",
                "wlan",
                "show",
                "interfaces"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout

        if "State" not in output:

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

        info = {}

        for line in output.splitlines():

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            info[key.strip()] = value.strip()

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

        return {

            "status": "Warning",

            "risk": "Low",

            "details": str(e),

            "recommendation": (
                "Unable to determine wireless security configuration."
            ),

            "detection_method": "netsh",

            "confidence": "Low",

            "data": {}

        }