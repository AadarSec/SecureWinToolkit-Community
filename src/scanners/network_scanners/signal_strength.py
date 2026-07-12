"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Signal Strength
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
                    "Connect to a wireless network to evaluate signal quality."
                ),
                "detection_method": "netsh wlan show interfaces",
                "confidence": "High",
                "data": {}
            }

        signal = info.get("Signal", "Unknown")
        rx_rate = info.get("Receive rate (Mbps)", "Unknown")
        tx_rate = info.get("Transmit rate (Mbps)", "Unknown")

        try:

            signal_percent = int(signal.replace("%", "").strip())

        except Exception:

            signal_percent = -1

        quality = "Unknown"
        status = "Information"
        risk = "Informational"

        if signal_percent >= 90:

            quality = "Excellent"
            status = "Passed"
            risk = "Low"

        elif signal_percent >= 75:

            quality = "Good"
            status = "Passed"
            risk = "Low"

        elif signal_percent >= 50:

            quality = "Fair"
            status = "Warning"
            risk = "Medium"

        elif signal_percent >= 0:

            quality = "Poor"
            status = "Warning"
            risk = "High"

        assessment = (
            f"Current wireless signal quality is {quality}."
        )

        details = (
            f"Signal Strength : {signal}\n\n"
            f"Receive Rate : {rx_rate} Mbps\n\n"
            f"Transmit Rate : {tx_rate} Mbps\n\n"
            f"Connection Quality : {quality}"
        )

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": assessment,

            "detection_method": "netsh wlan show interfaces",

            "confidence": "High",

            "data": {

                "signal": signal,
                "receive_rate": rx_rate,
                "transmit_rate": tx_rate,
                "quality": quality

            }

        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to determine wireless signal quality.",
            "netsh",
        )
