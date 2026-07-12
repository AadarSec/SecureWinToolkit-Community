"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    SSID
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
                    "Connect to a wireless network to collect "
                    "connection information."
                ),
                "detection_method": "netsh wlan show interfaces",
                "confidence": "High",
                "data": {}
            }

        interface = info.get("Name", "Unknown")
        ssid = info.get("SSID", "Unknown")
        bssid = info.get("BSSID", "Unknown")
        state = info.get("State", "Unknown")
        channel = info.get("Channel", "Unknown")

        band = "Unknown"

        try:

            ch = int(channel)

            if ch <= 14:
                band = "2.4 GHz"

            elif ch <= 177:
                band = "5 GHz"

            else:
                band = "6 GHz"

        except Exception:

            pass

        details = (
            f"Interface : {interface}\n\n"
            f"SSID : {ssid}\n\n"
            f"BSSID : {bssid}\n\n"
            f"Connection State : {state.title()}\n\n"
            f"Channel : {channel}\n\n"
            f"Band : {band}"
        )

        return {

            "status": "Information",

            "risk": "Informational",

            "details": details,

            "recommendation": (
                "Wireless connection information collected successfully."
            ),

            "detection_method": "netsh wlan show interfaces",

            "confidence": "High",

            "data": {

                "interface": interface,
                "ssid": ssid,
                "bssid": bssid,
                "state": state,
                "channel": channel,
                "band": band

            }

        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to retrieve wireless connection information.",
            "netsh",
        )
