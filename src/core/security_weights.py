"""
SecureWin Toolkit

Security Weight Configuration

This module contains the configuration used by
the Security Score Engine.

Changing values in this file automatically affects:

• Windows Audit Score
• Network Audit Score
• Overall Security Score
• Security Posture
"""

from __future__ import annotations


# ==========================================================
# MODULE WEIGHTS
# ==========================================================

MODULE_WEIGHTS = {

    "Windows Audit": 60,

    "Network Audit": 40

}


# ==========================================================
# CATEGORY WEIGHTS
# ==========================================================

CATEGORY_WEIGHTS = {

    # ---------------- Windows Audit ----------------

    "Identity & Access Security": 20,

    "System Protection": 30,

    "Windows Connectivity": 15,

    "System Configuration": 5,

    "Remote Access Security": 15,

    "Legacy Services": 10,

    "System Information": 0,

    # ---------------- Network Audit ----------------

    "Network Information": 0,

    "Network Configuration": 5,

    "Network Security": 20,

    "Wireless Information": 0,

    "Wireless Security": 15,

    "Network Exposure": 15,

    "Connection Analysis": 0

}


# ==========================================================
# STATUS PENALTIES
# ==========================================================

STATUS_PENALTIES = {

    "Passed": 0,

    "Information": 0,

    "Warning": 50,

    "Critical": 100

}


# ==========================================================
# SEVERITY MULTIPLIERS
# ==========================================================

SEVERITY_MULTIPLIERS = {

    0: 0.0,

    1: 0.0,

    2: 0.25,

    3: 0.50,

    4: 0.75,

    5: 1.00

}


# ==========================================================
# SECURITY POSTURE THRESHOLDS
# ==========================================================

SECURITY_POSTURE = {

    "Excellent": {

        "min_score": 95,

        "max_score": 100,

        "color": "#00C853"

    },

    "Strong": {

        "min_score": 85,

        "max_score": 94,

        "color": "#4CAF50"

    },

    "Good": {

        "min_score": 70,

        "max_score": 84,

        "color": "#FFC107"

    },

    "Fair": {

        "min_score": 55,

        "max_score": 69,

        "color": "#FF9800"

    },

    "Poor": {

        "min_score": 40,

        "max_score": 54,

        "color": "#FF5722"

    },

    "Critical": {

        "min_score": 0,

        "max_score": 39,

        "color": "#D32F2F"

    }

}


# ==========================================================
# SCORE LIMITS
# ==========================================================

MAX_SCORE = 100

MIN_SCORE = 0


# ==========================================================
# DEFAULT VALUES
# ==========================================================

DEFAULT_SECURITY_SCORE = 100

DEFAULT_POSTURE = "Excellent"


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def get_module_weight(module: str) -> int:
    """
    Returns weight for a module.
    """
    return MODULE_WEIGHTS.get(module, 0)


def get_category_weight(category: str) -> int:
    """
    Returns weight for a category.
    """
    return CATEGORY_WEIGHTS.get(category, 0)


def get_status_penalty(status: str) -> int:
    """
    Returns penalty value for scanner status.
    """
    return STATUS_PENALTIES.get(status, 0)


def get_severity_multiplier(severity: int) -> float:
    """
    Returns multiplier for severity.
    """
    return SEVERITY_MULTIPLIERS.get(severity, 0.0)


def get_security_posture(score: float) -> dict:
    """
    Returns posture information based on score.
    """

    for posture, data in SECURITY_POSTURE.items():

        if data["min_score"] <= score <= data["max_score"]:

            return {

                "name": posture,

                "color": data["color"]

            }

    return {

        "name": DEFAULT_POSTURE,

        "color": SECURITY_POSTURE[DEFAULT_POSTURE]["color"]

    }


def clamp_score(score: float) -> float:
    """
    Ensures score remains between 0 and 100.
    """

    return max(
        MIN_SCORE,
        min(MAX_SCORE, score)
    )
