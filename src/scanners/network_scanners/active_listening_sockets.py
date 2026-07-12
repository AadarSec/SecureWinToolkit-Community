"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Active Listening Sockets
"""

from __future__ import annotations

from .helpers import (
    build_error_result,
    get_netstat_connections,
    get_process_name_map,
)


def run_scan():

    try:

        connections = get_netstat_connections()
        process_map = get_process_name_map()

        sockets = []

        for conn in connections:

            if conn["state"] != "LISTENING":
                continue

            sockets.append({
                "local": conn["local"],
                "pid": conn["pid"],
                "process": process_map.get(conn["pid"], "Unknown"),
            })

        total = len(sockets)

        status = "Information"
        risk = "Informational"

        details = (
            f"Listening Sockets : {total}\n\n"
        )

        max_display = 20

        for socket in sockets[:max_display]:

            address = socket["local"]

            if ":" in address:

                host, port = address.rsplit(":", 1)

            else:

                host = address
                port = "Unknown"

            details += (
                f"Local Address : {host}\n"
                f"Port : {port}\n"
                f"Process : {socket['process']}\n"
                f"PID : {socket['pid']}\n\n"
            )

        if total > max_display:

            details += (
                f"... and {total - max_display} more listening socket(s)."
            )

        recommendation = (
            "Listening socket information was collected successfully."
        )

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": recommendation,

            "detection_method": "netstat -ano + tasklist",

            "confidence": "High",

            "data": {

                "total_sockets": total,

                "listening_sockets": sockets

            }

        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to enumerate active listening sockets.",
            "netstat -ano + tasklist",
        )
