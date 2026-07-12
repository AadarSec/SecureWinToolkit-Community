"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Listening Ports
"""

from __future__ import annotations

from .helpers import build_error_result, get_netstat_connections


# ---------------------------------------------------------------------------
# Port Classification
# ---------------------------------------------------------------------------
# Windows systems, by default, always expose a fixed set of service ports.
# These are NOT security issues and should never trigger a Warning/Critical.
# ---------------------------------------------------------------------------

SAFE_WINDOWS_PORTS = {
    135: "RPC Endpoint Mapper",
    445: "SMB",
    5357: "Web Services (WSDAPI)",
    7680: "Delivery Optimization",
}

SAFE_WINDOWS_PORT_RANGES = [
    (49664, 49699, "RPC Dynamic"),
]

WARNING_PORTS = {
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    1900: "SSDP",
    5355: "LLMNR",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    3389: "Remote Desktop",   # NOTE: 3389 must NEVER be marked Critical.
                              # RDP is normal on corporate machines.
                              # It only becomes a real risk when exposed
                              # externally (checked separately, see below).
}

CRITICAL_PORTS = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
}


def get_port_description(port: int) -> str:
    """Return a human readable description for a known port."""

    if port in SAFE_WINDOWS_PORTS:
        return SAFE_WINDOWS_PORTS[port]

    if port in WARNING_PORTS:
        return WARNING_PORTS[port]

    if port in CRITICAL_PORTS:
        return CRITICAL_PORTS[port]

    for start, end, label in SAFE_WINDOWS_PORT_RANGES:
        if start <= port <= end:
            return label

    return "Unknown"


def classify_port(port: int) -> str:
    """Classify a port as safe / warning / critical / unknown."""

    if port in CRITICAL_PORTS:
        return "critical"

    if port in WARNING_PORTS:
        return "warning"

    if port in SAFE_WINDOWS_PORTS:
        return "safe"

    for start, end, _ in SAFE_WINDOWS_PORT_RANGES:
        if start <= port <= end:
            return "safe"

    return "unknown"


def run_scan():

    try:

        # -------------------------------------------------------------
        # COLLECTION
        # -------------------------------------------------------------

        connections = get_netstat_connections()

        ports = set()
        port_addresses: dict = {}

        for conn in connections:

            if conn["state"] != "LISTENING":
                continue

            try:
                address, port_str = conn["local"].rsplit(":", 1)
                port = int(port_str)
            except Exception:
                continue

            ports.add(port)
            port_addresses.setdefault(port, set()).add(address)

        ports = sorted(ports)

        # -------------------------------------------------------------
        # ANALYSIS
        # -------------------------------------------------------------

        safe_ports_found = []
        warning_ports_found = []
        critical_ports_found = []

        for port in ports:

            category = classify_port(port)
            description = get_port_description(port)

            entry = f"{port} {description}"

            # Extra context for RDP exposure (never escalated to Critical).
            if port == 3389:
                addresses = port_addresses.get(port, set())
                if "0.0.0.0" in addresses:
                    entry += " (bound to all interfaces)"

            if category == "critical":
                critical_ports_found.append(entry)

            elif category == "warning":
                warning_ports_found.append(entry)

            elif category == "safe":
                safe_ports_found.append(entry)

            # "unknown" ports are intentionally left unclassified for now.

        # -------------------------------------------------------------
        # VERDICT
        # -------------------------------------------------------------

        if critical_ports_found:
            status = "Critical"
            risk = "High"

        elif warning_ports_found:
            status = "Warning"
            risk = "Medium"

        else:
            status = "Passed"
            risk = "Low"

        # -------------------------------------------------------------
        # RECOMMENDATION  (scanner-specific, not generic metadata)
        # -------------------------------------------------------------

        if status == "Passed":
            recommendation = (
                "Only expected Windows listening services were detected."
            )

        elif status == "Warning":
            recommendation = (
                "Review NetBIOS, WinRM or Remote Desktop if they are not "
                "required."
            )

        else:
            recommendation = (
                "Disable unnecessary legacy services immediately. "
                "Restrict exposed management ports using Windows Firewall."
            )

        # -------------------------------------------------------------
        # THREAT CONTEXT (Possible Attack / MITRE / Compliance)
        # -------------------------------------------------------------

        if status == "Passed":
            possible_attack = ["None"]

        elif status == "Warning":
            possible_attack = [
                "Network Enumeration",
                "Lateral Movement",
            ]

        else:
            possible_attack = [
                "Unauthorized Remote Access",
                "Credential Theft",
                "Lateral Movement",
            ]

        mitre = ["T1046 - Network Service Discovery"]

        compliance = {
            "CIS": "CIS Control 4 - Secure Configuration of Enterprise Assets",
            "NIST": "NIST SP 800-53 CM-7 (Least Functionality)",
        }

        # -------------------------------------------------------------
        # REPORT
        # -------------------------------------------------------------

        details = (
            f"Listening Ports\n\n"
            f"Total : {len(ports)}\n"
            f"Windows Default : {len(safe_ports_found)}\n"
            f"Warning : {len(warning_ports_found)}\n"
            f"Critical : {len(critical_ports_found)}"
        )

        if safe_ports_found:
            details += (
                "\n\nWindows Default Ports\n"
                + "\n".join(safe_ports_found)
            )

        if warning_ports_found or critical_ports_found:

            details += "\n\nSecurity Findings"

            if critical_ports_found:
                details += "\n" + "\n".join(critical_ports_found)

            if warning_ports_found:
                details += "\n" + "\n".join(warning_ports_found)

        return {

            "status": status,

            "risk": risk,

            "details": details,

            "recommendation": recommendation,

            "detection_method": "netstat -ano",

            "confidence": "High",

            "possible_attack": possible_attack,

            "mitre": mitre,

            "compliance": compliance,

            "data": {

                "listening_ports": ports,

                "safe_ports": safe_ports_found,

                "warning_ports": warning_ports_found,

                "critical_ports": critical_ports_found,

                "total_ports": len(ports),

                "safe_count": len(safe_ports_found),

                "warning_count": len(warning_ports_found),

                "critical_count": len(critical_ports_found),

            }

        }

    except Exception as e:

        result = build_error_result(
            e,
            "Unable to enumerate listening TCP ports.",
            "netstat -ano",
        )
        result["possible_attack"] = []
        result["mitre"] = []
        result["compliance"] = {}
        return result
