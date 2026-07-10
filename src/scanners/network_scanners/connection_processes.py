"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Connection Processes
"""

from __future__ import annotations

import subprocess
from collections import defaultdict


def get_process_name(pid):

    try:

        result = subprocess.run(

            [
                "tasklist",
                "/FI",
                f"PID eq {pid}",
                "/FO",
                "CSV",
                "/NH"
            ],

            capture_output=True,

            text=True,

            timeout=10

        )

        line = result.stdout.strip()

        if not line:
            return "Unknown"

        if "INFO:" in line:
            return "Unknown"

        return line.split(",")[0].replace('"', "")

    except Exception:

        return "Unknown"


def run_scan():

    try:

        result = subprocess.run(

            ["netstat", "-ano"],

            capture_output=True,

            text=True,

            timeout=15

        )

        process_connections = defaultdict(int)

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line.startswith("TCP"):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            if parts[3] != "ESTABLISHED":
                continue

            pid = parts[4]

            process_connections[pid] += 1

        processes = []

        for pid, connection_count in process_connections.items():

            process_name = get_process_name(pid)

            processes.append({

                "pid": pid,

                "process": process_name,

                "connections": connection_count

            })

        processes.sort(

            key=lambda x: x["connections"],

            reverse=True

        )

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

        return {

            "status": "Warning",

            "risk": "Low",

            "details": str(e),

            "recommendation": (
                "Unable to enumerate processes with active network connections."
            ),

            "detection_method": "netstat -ano + tasklist",

            "confidence": "Low",

            "data": {}

        }