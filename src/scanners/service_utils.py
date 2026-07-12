"""
SecureWin Toolkit
Shared Windows service status helper.

Several scanners only ever did one thing: `(Get-Service <name>).Status`
(or `Status,StartType`) via a full PowerShell spawn. `psutil` -- already a
project dependency (see requirements.txt) -- exposes the exact same
information through `psutil.win_service_get()`, which talks to the Windows
Service Control Manager directly (via the Win32 API) with no subprocess at
all. That turns a ~150-400ms PowerShell round-trip into a sub-millisecond
in-process call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import psutil


@dataclass
class ServiceInfo:
    exists: bool
    status: str = "unknown"        # e.g. "running", "stopped"
    start_type: str = "unknown"    # e.g. "automatic", "manual", "disabled"
    error: Optional[str] = None


def get_service_info(name: str) -> ServiceInfo:
    """
    Return the status/start type of a Windows service by its short
    (service) name, e.g. "Spooler", "WinRM", "RemoteRegistry".
    """

    try:
        svc = psutil.win_service_get(name)
        details = svc.as_dict()
        return ServiceInfo(
            exists=True,
            status=(details.get("status") or "unknown").lower(),
            start_type=(details.get("start_type") or "unknown").lower(),
        )
    except psutil.NoSuchProcess:
        return ServiceInfo(exists=False, status="not_installed")
    except Exception as e:
        return ServiceInfo(exists=False, error=str(e))
