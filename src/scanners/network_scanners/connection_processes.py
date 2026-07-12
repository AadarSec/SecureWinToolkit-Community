"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Connection Processes
"""

from __future__ import annotations

from collections import Counter

from .helpers import (
    build_error_result,
    get_netstat_connections,
    get_process_name_map,
)


def run_scan():

    try:

        connections = get_netstat_connections()
        process_map = get_process_name_map()

        established_pids = [
            conn["pid"]
            for conn in connections
            if conn["state"] == "ESTABLISHED"
        ]

        connection_counts = Counter(established_pids)

        processes = [
            {
                "pid": pid,
                "process": process_map.get(pid, "Unknown"),
                "connections": count,
            }
            for pid, count in connection_counts.items()
        ]

        processes.sort(key=lambda x: x["connections"], reverse=True)

        total_processes = len(processes)

        status = "Information"
        risk = "Informational"

        details = (
            f"Processes with Active Network Connections : "
            f"{total_processes}\n\n"
        )

        max_display = 20

        for process in processes[:max_display]:

            details += (
                f"Process : {process['process']}\n"
                f"PID : {process['pid']}\n"
                f"Active Connections : {process['connections']}\n\n"
            )

        if total_processes > max_display:

            details += (
                f"... and "
                f"{total_processes - max_display} more process(es)."
            )

        recommendation = (
            "Processes with active network connections were identified successfully."
        )

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": recommendation,

            "detection_method": "netstat -ano + tasklist",

            "confidence": "High",

            "data": {

                "total_processes": total_processes,

                "processes": processes

            }

        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to enumerate processes with active network connections.",
            "netstat -ano + tasklist",
        )
