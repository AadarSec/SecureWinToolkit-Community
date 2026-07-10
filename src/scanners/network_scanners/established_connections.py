"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Established Connections
"""

from __future__ import annotations

import subprocess
import re


def run_scan():

    try:

        result = subprocess.run(
            [
                "netstat",
                "-ano"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout

        connections = []

        for line in output.splitlines():

            line = line.strip()

            if not line.startswith("TCP"):
                continue

            if "ESTABLISHED" not in line:
                continue

            parts = re.split(r"\s+", line)

            if len(parts) < 5:
                continue

            local = parts[1]
            remote = parts[2]
            state = parts[3]
            pid = parts[4]

            connections.append(
                {
                    "local": local,
                    "remote": remote,
                    "pid": pid
                }
            )

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

        return {

            "status": "Warning",

            "risk": "Low",

            "details": str(e),

            "recommendation": (
                "Unable to enumerate established TCP connections."
            ),

            "detection_method": "netstat -ano",

            "confidence": "Low",

            "data": {}

        }