"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Established Connections
"""

from __future__ import annotations

from .helpers import build_error_result, get_netstat_connections


def run_scan():

    try:

        all_connections = get_netstat_connections()

        connections = [
            {
                "local": conn["local"],
                "remote": conn["remote"],
                "pid": conn["pid"],
            }
            for conn in all_connections
            if conn["state"] == "ESTABLISHED"
        ]

        total = len(connections)

        status = "Information"
        risk = "Informational"

        if total > 100:

            status = "Warning"
            risk = "Medium"

        elif total > 50:

            status = "Information"
            risk = "Low"

        details = f"Established TCP Connections : {total}\n\n"

        if connections:

            max_display = 20

            for conn in connections[:max_display]:

                details += (
                    f"Local : {conn['local']}\n"
                    f"Remote : {conn['remote']}\n"
                    f"PID : {conn['pid']}\n\n"
                )

            if total > max_display:

                details += (
                    f"... and {total - max_display} more connection(s)."
                )

        else:

            details += "No established TCP connections were found."

        recommendation = (
            "Current active TCP connections were collected successfully."
        )

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": recommendation,

            "detection_method": "netstat -ano",

            "confidence": "High",

            "data": {

                "total_connections": total,

                "connections": connections

            }

        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to enumerate established TCP connections.",
            "netstat -ano",
        )
