"""
SecureWin Toolkit
Network Audit Scanner

Scanner:
    Network Services

NOTE:
    This file was uploaded empty. Its purpose overlaps entirely with
    `running_network_services.py` (same "Running Network Services" scan),
    so rather than duplicating that scanning logic here, this module
    simply re-exports it. If this file was meant to do something
    different, let me know and I'll write dedicated logic for it instead.
"""

from __future__ import annotations

from .running_network_services import run_scan  # noqa: F401
