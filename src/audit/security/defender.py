from src.audit.models import AuditResult
from src.utils.powershell import run_powershell


def audit_defender():

    command = """
    Get-MpComputerStatus |
    Select-Object AMRunningMode,
                  RealTimeProtectionEnabled,
                  AntivirusEnabled,
                  AntispywareEnabled
    """

    result = run_powershell(command)

    if not result["success"]:

        return AuditResult(
            name="Windows Defender",
            status="Critical",
            value="Unknown",
            recommendation="Unable to retrieve Windows Defender status.",
            details=result["stderr"],
        )

    output = result["stdout"]

    enabled = "True" in output

    if enabled:

        return AuditResult(
            name="Windows Defender",
            status="Pass",
            value="Enabled",
            recommendation="No action required.",
            details=output,
        )

    return AuditResult(
        name="Windows Defender",
        status="Critical",
        value="Disabled",
        recommendation="Enable Microsoft Defender Real-Time Protection.",
        details=output,
    )