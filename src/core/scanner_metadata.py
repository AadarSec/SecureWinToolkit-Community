"""
SecureWin Toolkit
Scanner Metadata Repository

This module contains metadata for every scanner used by
SecureWin Toolkit.

Used by:
    • Security Score Engine
    • Dashboard
    • Reports
    • Security Posture
    • Future Compliance Engine
"""

from __future__ import annotations


# ==========================================================
# MODULES
# ==========================================================

MODULE = {

    "WINDOWS": "Windows Audit",

    "NETWORK": "Network Audit"

}


# ==========================================================
# SCANNER TYPES
# ==========================================================

SCANNER_TYPE = {

    "SECURITY": "Security",

    "CONFIGURATION": "Configuration",

    "INFORMATION": "Information"

}


# ==========================================================
# SEVERITY LEVELS
# ==========================================================

SEVERITY = {

    "NONE": 0,

    "INFORMATION": 1,

    "LOW": 2,

    "MEDIUM": 3,

    "HIGH": 4,

    "CRITICAL": 5

}


SEVERITY_LABELS = {

    0: "None",

    1: "Information",

    2: "Low",

    3: "Medium",

    4: "High",

    5: "Critical"

}


# ==========================================================
# SCANNER METADATA
# ==========================================================

SCANNER_METADATA = {

    # ======================================================
    # WINDOWS AUDIT
    # ======================================================

    # ------------------------------------------------------
    # Identity & Access Security
    # ------------------------------------------------------

    "Administrator Account": {

        "module": MODULE["WINDOWS"],

        "category": "Identity & Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 10,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Guest Account": {

        "module": MODULE["WINDOWS"],

        "category": "Identity & Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Password Policy": {

        "module": MODULE["WINDOWS"],

        "category": "Identity & Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 9,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # System Protection
    # ------------------------------------------------------

    "UAC": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 6,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "BitLocker": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 10,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Secure Boot": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 9,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "TPM": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 9,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Credential Guard": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "SmartScreen": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 5,

        "severity": SEVERITY["MEDIUM"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Windows Defender": {

        "module": MODULE["WINDOWS"],

        "category": "System Protection",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 10,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Windows Connectivity
    # ------------------------------------------------------

    "Windows Firewall": {

        "module": MODULE["WINDOWS"],

        "category": "Windows Connectivity",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "SMBv1": {

        "module": MODULE["WINDOWS"],

        "category": "Windows Connectivity",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # System Configuration
    # ------------------------------------------------------

    "Windows Update": {

        "module": MODULE["WINDOWS"],

        "category": "System Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 5,

        "severity": SEVERITY["MEDIUM"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Network Discovery": {

        "module": MODULE["WINDOWS"],

        "category": "System Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 2,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "File & Printer Sharing": {

        "module": MODULE["WINDOWS"],

        "category": "System Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 2,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Remote Access Security
    # ------------------------------------------------------

    "Remote Desktop": {

        "module": MODULE["WINDOWS"],

        "category": "Remote Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 5,

        "severity": SEVERITY["MEDIUM"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Remote Assistance": {

        "module": MODULE["WINDOWS"],

        "category": "Remote Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 3,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Remote Registry": {

        "module": MODULE["WINDOWS"],

        "category": "Remote Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 7,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "WinRM": {

        "module": MODULE["WINDOWS"],

        "category": "Remote Access Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 4,

        "severity": SEVERITY["MEDIUM"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Legacy Services
    # ------------------------------------------------------

    "Print Spooler": {

        "module": MODULE["WINDOWS"],

        "category": "Legacy Services",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 2,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "SNMP": {

        "module": MODULE["WINDOWS"],

        "category": "Legacy Services",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 5,

        "severity": SEVERITY["MEDIUM"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Telnet": {

        "module": MODULE["WINDOWS"],

        "category": "Legacy Services",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "AutoRun": {

        "module": MODULE["WINDOWS"],

        "category": "Legacy Services",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 3,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Windows Event Log": {

        "module": MODULE["WINDOWS"],

        "category": "System Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    # ======================================================
    # NETWORK AUDIT
    # ======================================================

    # ------------------------------------------------------
    # Network Information
    # ------------------------------------------------------

    "Public IP Address": {

        "module": MODULE["NETWORK"],

        "category": "Network Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Default Gateway": {

        "module": MODULE["NETWORK"],

        "category": "Network Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "DNS Servers": {

        "module": MODULE["NETWORK"],

        "category": "Network Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "DHCP Status": {

        "module": MODULE["NETWORK"],

        "category": "Network Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "MAC Address": {

        "module": MODULE["NETWORK"],

        "category": "Network Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Network Configuration
    # ------------------------------------------------------

    "Active Network Adapter": {

        "module": MODULE["NETWORK"],

        "category": "Network Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 0,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Adapter Speed": {

        "module": MODULE["NETWORK"],

        "category": "Network Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 0,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "IPv6 Status": {

        "module": MODULE["NETWORK"],

        "category": "Network Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 1,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "MTU": {

        "module": MODULE["NETWORK"],

        "category": "Network Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 1,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Network Profile (Public / Private)": {

        "module": MODULE["NETWORK"],

        "category": "Network Configuration",

        "type": SCANNER_TYPE["CONFIGURATION"],

        "weight": 2,

        "severity": SEVERITY["LOW"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Network Security
    # ------------------------------------------------------

    "Firewall Network Policy": {

        "module": MODULE["NETWORK"],

        "category": "Network Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "DNS Security": {

        "module": MODULE["NETWORK"],

        "category": "Network Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 6,

        "severity": SEVERITY["MEDIUM"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "LLMNR": {

        "module": MODULE["NETWORK"],

        "category": "Network Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "NetBIOS": {

        "module": MODULE["NETWORK"],

        "category": "Network Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 7,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Wireless Information
    # ------------------------------------------------------

    "SSID": {

        "module": MODULE["NETWORK"],

        "category": "Wireless Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Signal Strength": {

        "module": MODULE["NETWORK"],

        "category": "Wireless Information",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Wireless Security
    # ------------------------------------------------------

    "Wi-Fi Encryption": {

        "module": MODULE["NETWORK"],

        "category": "Wireless Security",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 9,

        "severity": SEVERITY["CRITICAL"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Network Exposure
    # ------------------------------------------------------

    "Listening Ports": {

        "module": MODULE["NETWORK"],

        "category": "Network Exposure",

        "type": SCANNER_TYPE["SECURITY"],

        "weight": 8,

        "severity": SEVERITY["HIGH"],

        "enabled_for_score": True,

        "dashboard": True,

        "report": True

    },

    "Running Network Services": {

        "module": MODULE["NETWORK"],

        "category": "Network Exposure",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    # ------------------------------------------------------
    # Connection Analysis
    # ------------------------------------------------------

    "Established Connections": {

        "module": MODULE["NETWORK"],

        "category": "Connection Analysis",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Remote Endpoints": {

        "module": MODULE["NETWORK"],

        "category": "Connection Analysis",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Connection Processes": {

        "module": MODULE["NETWORK"],

        "category": "Connection Analysis",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    },

    "Active Listening Sockets": {

        "module": MODULE["NETWORK"],

        "category": "Connection Analysis",

        "type": SCANNER_TYPE["INFORMATION"],

        "weight": 0,

        "severity": SEVERITY["INFORMATION"],

        "enabled_for_score": False,

        "dashboard": True,

        "report": True

    }

}


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def scanner_exists(scanner_name: str) -> bool:
    """
    Check whether a scanner exists.
    """
    return scanner_name in SCANNER_METADATA


def get_scanner_metadata(scanner_name: str) -> dict:
    """
    Returns metadata for a scanner.
    """
    return SCANNER_METADATA.get(scanner_name, {})


def get_scanner_module(scanner_name: str) -> str:
    """
    Returns scanner module.
    """
    return get_scanner_metadata(scanner_name).get("module", "")


def get_scanner_category(scanner_name: str) -> str:
    """
    Returns scanner category.
    """
    return get_scanner_metadata(scanner_name).get("category", "")


def get_scanner_type(scanner_name: str) -> str:
    """
    Returns scanner type.
    """
    return get_scanner_metadata(scanner_name).get("type", "")


def get_scanner_weight(scanner_name: str) -> int:
    """
    Returns scanner weight.
    """
    return get_scanner_metadata(scanner_name).get("weight", 0)


def get_scanner_severity(scanner_name: str) -> int:
    """
    Returns scanner severity.
    """
    return get_scanner_metadata(scanner_name).get("severity", 0)


def get_severity_label(severity: int) -> str:
    """
    Converts numeric severity into text.
    """
    return SEVERITY_LABELS.get(severity, "Unknown")


def is_score_enabled(scanner_name: str) -> bool:
    """
    True if scanner contributes to security score.
    """
    return get_scanner_metadata(scanner_name).get(
        "enabled_for_score",
        False
    )


def is_dashboard_enabled(scanner_name: str) -> bool:
    """
    True if scanner appears on dashboard.
    """
    return get_scanner_metadata(scanner_name).get(
        "dashboard",
        False
    )


def is_report_enabled(scanner_name: str) -> bool:
    """
    True if scanner appears in reports.
    """
    return get_scanner_metadata(scanner_name).get(
        "report",
        False
    )


# ==========================================================
# COLLECTION HELPERS
# ==========================================================

def get_module_scanners(module: str) -> dict:
    """
    Returns all scanners for a module.
    """
    return {
        name: metadata
        for name, metadata in SCANNER_METADATA.items()
        if metadata["module"] == module
    }


def get_category_scanners(category: str) -> dict:
    """
    Returns all scanners in a category.
    """
    return {
        name: metadata
        for name, metadata in SCANNER_METADATA.items()
        if metadata["category"] == category
    }


def get_scanners_by_type(scanner_type: str) -> dict:
    """
    Returns all scanners of a specific type.
    """
    return {
        name: metadata
        for name, metadata in SCANNER_METADATA.items()
        if metadata["type"] == scanner_type
    }


def get_security_scanners() -> dict:
    """
    Returns Security scanners.
    """
    return get_scanners_by_type(
        SCANNER_TYPE["SECURITY"]
    )


def get_configuration_scanners() -> dict:
    """
    Returns Configuration scanners.
    """
    return get_scanners_by_type(
        SCANNER_TYPE["CONFIGURATION"]
    )


def get_information_scanners() -> dict:
    """
    Returns Information scanners.
    """
    return get_scanners_by_type(
        SCANNER_TYPE["INFORMATION"]
    )


def get_score_enabled_scanners() -> dict:
    """
    Returns all scanners that affect security score.
    """
    return {
        name: metadata
        for name, metadata in SCANNER_METADATA.items()
        if metadata["enabled_for_score"]
    }


def get_dashboard_scanners() -> dict:
    """
    Returns dashboard scanners.
    """
    return {
        name: metadata
        for name, metadata in SCANNER_METADATA.items()
        if metadata["dashboard"]
    }


def get_report_scanners() -> dict:
    """
    Returns report scanners.
    """
    return {
        name: metadata
        for name, metadata in SCANNER_METADATA.items()
        if metadata["report"]
    }


def get_total_scanner_count() -> int:
    """
    Returns total registered scanners.
    """
    return len(SCANNER_METADATA)


def get_module_count(module: str) -> int:
    """
    Returns total scanners in a module.
    """
    return len(
        get_module_scanners(module)
    )


def get_category_count(category: str) -> int:
    """
    Returns total scanners in a category.
    """
    return len(
        get_category_scanners(category)
    )


def get_security_scanner_count() -> int:
    """
    Returns total Security scanners.
    """
    return len(
        get_security_scanners()
    )


def get_configuration_scanner_count() -> int:
    """
    Returns total Configuration scanners.
    """
    return len(
        get_configuration_scanners()
    )


def get_information_scanner_count() -> int:
    """
    Returns total Information scanners.
    """
    return len(
        get_information_scanners()
    )
