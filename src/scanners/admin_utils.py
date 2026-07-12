"""
Admin-privilege check.

BEFORE: spawned a full powershell.exe process (~150-400ms) every single
time is_admin() was called, just to read one boolean the OS already
exposes directly via the Win32 API.

AFTER: calls shell32.IsUserAnAdmin() through ctypes -- a plain in-process
API call, effectively free (microseconds, no subprocess). The result is
also cached, since admin status cannot change during the process's
lifetime, so even repeated calls across many scanners cost nothing after
the first.
"""

import sys
from functools import lru_cache


@lru_cache(maxsize=1)
def is_admin() -> bool:
    """
    Returns True if the current process is running with
    Administrator privileges, False otherwise (including on any
    detection failure, to be safe).
    """

    if sys.platform != "win32":
        return False

    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
