"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Remote Endpoints
"""

from __future__ import annotations

import ipaddress

from .helpers import build_error_result, get_netstat_connections


IGNORED_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def run_scan():

    try:

        connections = get_netstat_connections()

        endpoints = set()

        for conn in connections:

            if conn["state"] != "ESTABLISHED":
                continue

            remote = conn["remote"]

            if ":" not in remote:
                continue

            ip = remote.rsplit(":", 1)[0]

            if ip in IGNORED_IPS:
                continue

            endpoints.add(ip)

        endpoint_list = sorted(endpoints)

        public_count = 0
        private_count = 0
        loopback_count = 0

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

        return build_error_result(
            e,
            "Unable to enumerate remote endpoints.",
            "netstat -ano",
        )
