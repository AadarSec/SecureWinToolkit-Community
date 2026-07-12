"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Running Network Services
"""

from __future__ import annotations

from .helpers import build_error_result, run_powershell


# ---------------------------------------------------------------------------
# This scanner is INFORMATIONAL only.
# It does not evaluate risk — it simply reports the current state of
# core Windows networking services for audit/documentation purposes.
# ---------------------------------------------------------------------------

NETWORK_SERVICES = {
    "LanmanServer": "File and Printer Sharing (SMB Server)",
    "LanmanWorkstation": "SMB Client / Workstation Service",
    "Dnscache": "DNS Client Resolver Cache",
    "Dhcp": "DHCP Client",
    "NlaSvc": "Network Location Awareness",
    "WinHttpAutoProxySvc": "WinHTTP Web Proxy Auto-Discovery",
    "WlanSvc": "WLAN AutoConfig",
    "lmhosts": "TCP/IP NetBIOS Helper",
}


def run_scan():

    try:

        # -------------------------------------------------------------
        # COLLECTION
        # -------------------------------------------------------------
        # Single PowerShell call for all services instead of one call
        # per service — faster and more reliable. Uses the shared
        # run_powershell() helper instead of re-implementing the
        # subprocess + JSON parsing boilerplate.
        # -------------------------------------------------------------

        service_names = ",".join(f'"{name}"' for name in NETWORK_SERVICES)

        command = f"""
$names = @({service_names})
$results = foreach ($n in $names) {{
    $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($svc) {{
        [PSCustomObject]@{{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Status = $svc.Status.ToString()
        }}
    }} else {{
        [PSCustomObject]@{{
            Name = $n
            DisplayName = $n
            Status = "NotFound"
        }}
    }}
}}
$results | ConvertTo-Json
"""

        raw = run_powershell(command, timeout=15)

        # PowerShell returns a dict (not a list) when only one object exists.
        if isinstance(raw, dict):
            raw = [raw]

        # -------------------------------------------------------------
        # ANALYSIS
        # -------------------------------------------------------------

        services = []
        running = 0
        stopped = 0
        not_found = 0

        for item in raw:

            name = item.get("Name", "Unknown")
            display_name = item.get("DisplayName", name)
            status_text = str(item.get("Status", "Unknown"))
            description = NETWORK_SERVICES.get(name, "")

            if status_text.lower() == "running":
                running += 1

            elif status_text.lower() == "notfound":
                not_found += 1

            else:
                stopped += 1

            services.append({
                "name": name,
                "display_name": display_name,
                "description": description,
                "status": status_text,
            })

        total = len(services)

        # -------------------------------------------------------------
        # VERDICT
        # -------------------------------------------------------------
        # Purely informational — no pass/fail/critical judgement is made.
        # -------------------------------------------------------------

        status = "Information"
        risk = "Informational"

        recommendation = (
            "This is an informational scan. No action is required. "
            "Review the service states below to confirm they match your "
            "expected network configuration."
        )

        # -------------------------------------------------------------
        # THREAT / COMPLIANCE CONTEXT
        # -------------------------------------------------------------

        possible_attack = ["None (Informational Scan)"]
        mitre = ["T1007 - System Service Discovery"]
        compliance = {
            "CIS": "CIS Control 4 - Secure Configuration of Enterprise Assets",
            "NIST": "NIST SP 800-53 CM-8 (System Component Inventory)",
        }

        # -------------------------------------------------------------
        # REPORT
        # -------------------------------------------------------------

        details = (
            f"Total Services Checked : {total}\n"
            f"Running : {running}\n"
            f"Stopped : {stopped}\n"
            f"Not Found : {not_found}\n\n"
        )

        for service in services:
            details += (
                f"{service['display_name']}\n"
                f"Service Name : {service['name']}\n"
                f"Description  : {service['description'] or 'N/A'}\n"
                f"Status       : {service['status']}\n\n"
            )

        return {

            "status": status,

            "risk": risk,

            "details": details.strip(),

            "recommendation": recommendation,

            "detection_method": "PowerShell Get-Service",

            "confidence": "High",

            "possible_attack": possible_attack,

            "mitre": mitre,

            "compliance": compliance,

            "data": {

                "total_services": total,

                "running_services": running,

                "stopped_services": stopped,

                "not_found_services": not_found,

                "services": services,

            }

        }

    except Exception as e:

        result = build_error_result(
            e,
            "Unable to enumerate network-related Windows services.",
            "PowerShell Get-Service",
        )
        result["possible_attack"] = []
        result["mitre"] = []
        result["compliance"] = {}
        return result
