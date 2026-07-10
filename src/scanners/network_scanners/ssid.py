"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    SSID
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
                    "Connect to a wireless network to collect "
                    "connection information."
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

        return {

            "status": "Warning",

            "risk": "Low",

            "details": str(e),

            "recommendation": (
                "Unable to retrieve wireless connection information."
            ),

            "detection_method": "netsh",

            "confidence": "Low",

            "data": {}

        }
