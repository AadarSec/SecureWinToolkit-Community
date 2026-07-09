import subprocess


def is_admin():
    """
    Returns True if the current process is running with
    Administrator privileges, False otherwise (including on any
    detection failure, to be safe).
    """

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "([Security.Principal.WindowsPrincipal] "
                "[Security.Principal.WindowsIdentity]::GetCurrent())."
                "IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        return result.stdout.strip().lower() == "true"

    except Exception:
        return False
