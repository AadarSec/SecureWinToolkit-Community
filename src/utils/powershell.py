import subprocess


def run_powershell(command: str):
    """
    Execute a PowerShell command and return its output.
    """

    try:

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

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }

    except Exception as e:

        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
        }