"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Firewall Network Policy
"""

from __future__ import annotations

from .helpers import build_error_result, run_powershell


def run_scan():
    """
    Audits Windows Defender Firewall network policy.
    """

    powershell = r"""
$result = Get-NetFirewallProfile | Select-Object `
    Name,
    Enabled,
    DefaultInboundAction,
    DefaultOutboundAction

$result | ConvertTo-Json
"""

    try:

        profiles = run_powershell(powershell)

        if isinstance(profiles, dict):
            profiles = [profiles]

        details = []

        critical = False
        warning = False

        for profile in profiles:

            name = profile["Name"]

            enabled = profile["Enabled"]

            inbound = profile["DefaultInboundAction"]

            outbound = profile["DefaultOutboundAction"]

            details.append(
                f"{name}\n"
                f"  Enabled : {enabled}\n"
                f"  Inbound : {inbound}\n"
                f"  Outbound : {outbound}"
            )

            if not enabled:
                critical = True

            if str(inbound).lower() != "block":
                warning = True

        if critical:

            status = "Critical"
            risk = "High"

            recommendation = (
                "Enable Windows Defender Firewall on all network profiles."
            )

        elif warning:

            status = "Warning"
            risk = "Medium"

            recommendation = (
                "Review the default inbound firewall policy. "
                "Inbound traffic should normally be blocked."
            )

        else:

            status = "Passed"
            risk = "Low"

            recommendation = (
                "Firewall network policy follows Microsoft's recommended defaults."
            )

        return {
            "status": status,
            "risk": risk,
            "details": "\n\n".join(details),
            "recommendation": recommendation,
            "detection_method": "PowerShell Get-NetFirewallProfile",
            "confidence": "High",
            "data": {
                "profiles": profiles
            }
        }

    except Exception as e:

        return build_error_result(
            e,
            "Unable to retrieve firewall network policy.",
            "PowerShell Get-NetFirewallProfile",
        )
