"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Remote Endpoints
"""

from __future__ import annotations

import subprocess
import ipaddress


def run_scan():

    try:

        result = subprocess.run(

            ["netstat", "-ano"],

            capture_output=True,

            text=True,

            timeout=15

        )

        endpoints = set()

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line.startswith("TCP"):
                continue

            parts = line.split()

            if len(parts) < 4:
                continue

            if parts[3] != "ESTABLISHED":
                continue

            remote = parts[2]

            if ":" not in remote:
                continue

            ip = remote.rsplit(":", 1)[0]

            if ip in (
                "0.0.0.0",
                "127.0.0.1",
                "::",
                "::1"
            ):
                continue

            endpoints.add(ip)

        public_count = 0
        private_count = 0
        loopback_count = 0

        endpoint_list = sorted(endpoints)

        details = (
            f"Unique Remote Endpoints : {len(endpoint_list)}\n\n"
        )

        max_display = 20

        for ip in endpoint_list[:max_display]:

            try:

                ip_obj = ipaddress.ip_address(ip)

                if ip_obj.is_loopback:

                    endpoint_type = "Loopback"
                    loopback_count += 1

                elif ip_obj.is_private:

                    endpoint_type = "Private"
                    private_count += 1

                else:

                    endpoint_type = "Public"
                    public_count += 1

            except Exception:

                endpoint_type = "Unknown"

            details += f"{ip} ({endpoint_type})\n"

        if len(endpoint_list) > max_display:

            details += (
                f"\n... and {len(endpoint_list) - max_display} more endpoint(s)."
            )

        details += (

            f"\n\nPublic Endpoints : {public_count}"
            f"\nPrivate Endpoints : {private_count}"
            f"\nLoopback Endpoints : {loopback_count}"

        )

        status = "Information"
        risk = "Informational"

        recommendation = (
            "Remote endpoint information was collected successfully."
        )

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": recommendation,

            "detection_method": "netstat -ano",

            "confidence": "High",

            "data": {

                "total_endpoints": len(endpoint_list),

                "public_endpoints": public_count,

                "private_endpoints": private_count,

                "loopback_endpoints": loopback_count,

                "endpoints": endpoint_list

            }

        }

    except Exception as e:

        return {

            "status": "Warning",

            "risk": "Low",

            "details": str(e),

            "recommendation": (
                "Unable to enumerate remote endpoints."
            ),

            "detection_method": "netstat -ano",

            "confidence": "Low",

            "data": {}

        }