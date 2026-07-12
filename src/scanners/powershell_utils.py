"""
SecureWin Toolkit
Shared PowerShell execution helper.

Every scanner used to hand-roll its own `subprocess.run(["powershell", ...])`
call. That duplication had two real costs:

1. Correctness: none of the calls set `creationflags=CREATE_NO_WINDOW`, so on
   a packaged (non-console) build, Windows still has to allocate a console
   for each child process, which both flashes a window and adds measurable
   spawn overhead.
2. Performance: every scanner pays the ~150-400ms PowerShell/.NET startup
   cost from scratch. With 20+ scanners running back-to-back that is easily
   several seconds of pure process-startup overhead before any actual work
   happens.

This module centralizes the subprocess call so:
  - CREATE_NO_WINDOW is always set (no window flash, faster spawn).
  - Flags are consistent (-NoProfile -NonInteractive -ExecutionPolicy Bypass).
  - Callers get a small, typed result object instead of raw stdout/stderr.
  - Any future speed-up (e.g. swapping to `pwsh`, or a persistent PS
    session) only needs to change one place.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

# CREATE_NO_WINDOW only exists on Windows; guard for cross-platform dev/test.
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

_BASE_ARGS = [
    "powershell",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command",
]


@dataclass
class PSResult:
    stdout: str
    stderr: str
    returncode: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_ps(command: str, timeout: int = 15) -> PSResult:
    """
    Run a PowerShell command and return its (stripped) output.

    This is a drop-in replacement for the pattern that was repeated in
    every scanner:

        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()

    becomes:

        output = run_ps(command, timeout).stdout
    """

    try:
        result = subprocess.run(
            _BASE_ARGS + [command],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        return PSResult(
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            returncode=result.returncode,
        )
    except Exception as e:
        return PSResult(stdout="", stderr=str(e), returncode=-1)


def run_cmd(args: list[str], timeout: int = 15) -> PSResult:
    """
    Same idea as run_ps(), but for plain (non-PowerShell) commands such as
    `manage-bde -status`. Still suppresses the console window.
    """

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        return PSResult(
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            returncode=result.returncode,
        )
    except Exception as e:
        return PSResult(stdout="", stderr=str(e), returncode=-1)
