import subprocess


def check_windows_defender():

    try:

        command = """
$status = Get-MpComputerStatus

$service = Get-Service WinDefend -ErrorAction SilentlyContinue

$result = [PSCustomObject]@{

    ServiceRunning = if($service){$service.Status}else{"Unknown"}

    StartupType = if($service){$service.StartType}else{"Unknown"}

    RealTimeProtection = $status.RealTimeProtectionEnabled

    AntivirusEnabled = $status.AntivirusEnabled

    BehaviorMonitor = $status.BehaviorMonitorEnabled

    IOAVProtection = $status.IoavProtectionEnabled

    ScriptScanning = $status.AntispywareEnabled

    AntivirusSignatureVersion = $status.AntivirusSignatureVersion

    AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated

    AntivirusEngineVersion = $status.AMEngineVersion
}

$result | ConvertTo-Json -Compress
"""

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )

        if result.returncode != 0:

            return {
                "status": "Warning",
                "risk": "Unknown",
                "details": result.stderr.strip(),
                "recommendation": "Verify Microsoft Defender manually.",
                "detection_method": "Get-MpComputerStatus",
                "confidence": "0%",
            }

        import json

        data = json.loads(result.stdout)

        findings = []

        # -------------------------
        # Service
        # -------------------------

        service_running = str(data["ServiceRunning"])
        # Convert PowerShell enum values

        if service_running == "4":
            service_running = "Running"

        elif service_running == "1":
            service_running = "Stopped"

        startup_type = str(data["StartupType"])

        if startup_type == "2":
            startup_type = "Automatic"

        elif startup_type == "3":
            startup_type = "Manual"

        elif startup_type == "4":
            startup_type = "Disabled"

        if service_running.lower() != "running":

            findings.append(
                "Microsoft Defender Antivirus service is not running."
            )

        # -------------------------
        # Real-Time Protection
        # -------------------------

        if not data["RealTimeProtection"]:

            findings.append(
                "Real-Time Protection is disabled."
            )

        # -------------------------
        # Antivirus
        # -------------------------

        if not data["AntivirusEnabled"]:

            findings.append(
                "Microsoft Defender Antivirus is disabled."
            )

        # -------------------------
        # Behavior Monitoring
        # -------------------------

        if not data["BehaviorMonitor"]:

            findings.append(
                "Behavior Monitoring is disabled."
            )

        # -------------------------
        # IOAV
        # -------------------------

        if not data["IOAVProtection"]:

            findings.append(
                "IOAV Protection is disabled."
            )

        # -------------------------
        # Final Result
        # -------------------------

        if findings:

            status = "Critical"
            risk = "High"

            details = "\n".join(findings)

            recommendation = (
                "Enable all Microsoft Defender protection features."
            )

        else:

            status = "Passed"
            risk = "Low"

            details = (
                "Microsoft Defender is fully operational."
            )

            recommendation = (
                "No action required."
            )

        details += (

            "\n\n"

            "Protection Status\n"
            "-------------------------\n"

            f"Service Running            : {service_running}\n"
            f"Startup Type               : {startup_type}\n"
            f"Real-Time Protection       : {data['RealTimeProtection']}\n"
            f"Antivirus Enabled          : {data['AntivirusEnabled']}\n"
            f"Behavior Monitoring        : {data['BehaviorMonitor']}\n"
            f"IOAV Protection            : {data['IOAVProtection']}\n"
            f"Script Scanning            : {data['ScriptScanning']}\n\n"

            "Version Information\n"
            "-------------------------\n"

            f"Engine Version             : {data['AntivirusEngineVersion']}\n"
            f"Signature Version          : {data['AntivirusSignatureVersion']}\n"
            f"Signature Updated          : {data['AntivirusSignatureLastUpdated']}"
        )

        return {

            "status": status,
            "risk": risk,
            "details": details,
            "recommendation": recommendation,
            "detection_method": "Get-MpComputerStatus + Get-Service",
            "confidence": "100%",
        }

    except Exception as e:

        return {

            "status": "Warning",
            "risk": "Unknown",

            "details": f"Windows Defender check failed.\n\n{e}",

            "recommendation": "Verify Microsoft Defender manually.",

            "detection_method": "Get-MpComputerStatus",

            "confidence": "0%",
        }