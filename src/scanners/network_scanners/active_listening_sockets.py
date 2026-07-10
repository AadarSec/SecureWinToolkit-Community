"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Active Listening Sockets
"""

from __future__ import annotations

import subprocess


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

        if not line or "INFO:" in line:
            return "Unknown"

        return line.split(",")[0].replace('"', "")

    except Exception:

        return "Unknown"


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

        sockets = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line.startswith("TCP"):
                continue

            if "LISTENING" not in line:
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            local = parts[1]
            pid = parts[4]

            process = get_process_name(pid)

            sockets.append({

                "local": local,

                "pid": pid,

                "process": process

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

        return {

            "status": "Warning",

            "risk": "Low",

            "details": str(e),

            "recommendation": (
                "Unable to enumerate active listening sockets."
            ),

            "detection_method": "netstat -ano + tasklist",

            "confidence": "Low",

            "data": {}

        }