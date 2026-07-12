"""
SecureWin Toolkit - Settings Service

Small persistent key/value store for app-wide preferences. Anything
the Settings page lets the user change lives here, and other modules
(ReportsPage, scheduler_service) read from here instead of hardcoding
defaults -- so a change in Settings actually takes effect elsewhere.
"""

from __future__ import annotations

import json
import os

from src.services import report_generator


SETTINGS_DIR = os.path.join(os.path.expanduser("~"), "SecureWinToolkit")
SETTINGS_PATH = os.path.join(SETTINGS_DIR, "settings.json")

os.makedirs(SETTINGS_DIR, exist_ok=True)


DEFAULTS = {
    # Report generation defaults (pre-selected on the Reports page)
    "default_audit_type": "windows",       # "windows" | "network"
    "default_report_format": "PDF",        # "PDF" | "HTML" | "CSV" | "JSON"
    "include_passed_by_default": True,
    "include_recommendations_by_default": True,
    "include_system_info_by_default": True,

    # Behavior
    "auto_open_report_after_generate": False,
    "confirm_before_running_audit": True,

    # Scheduler
    "scheduler_enabled": True,
    "scheduler_poll_seconds": 30,

    # Dashboard
    "dashboard_auto_refresh_seconds": 60,
}


def load_settings():
    """Returns the full settings dict, always containing every DEFAULTS key
    (missing keys are backfilled so older settings.json files don't break
    newer code that expects a new key)."""

    settings = dict(DEFAULTS)

    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
            settings.update(saved)
        except (json.JSONDecodeError, OSError):
            pass

    return settings


def save_settings(settings):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def get(key):
    return load_settings().get(key, DEFAULTS.get(key))


def set(key, value):
    settings = load_settings()
    settings[key] = value
    save_settings(settings)
    return settings


def update(**kwargs):
    settings = load_settings()
    settings.update(kwargs)
    save_settings(settings)
    return settings


def reset_to_defaults():
    save_settings(dict(DEFAULTS))
    return dict(DEFAULTS)


# ==========================================================
# DERIVED / READ-ONLY INFO the Settings page displays
# ==========================================================

def get_storage_info():
    """Real numbers pulled from disk -- reports folder size + count."""

    entries = report_generator.load_report_index()

    total_size_bytes = 0
    missing = 0
    for e in entries:
        path = e.get("filepath", "")
        if path and os.path.exists(path):
            total_size_bytes += os.path.getsize(path)
        else:
            missing += 1

    return {
        "report_count": len(entries),
        "missing_files": missing,
        "total_size": report_generator._human_size(total_size_bytes),
        "reports_dir": report_generator.REPORTS_DIR,
    }


def clear_report_history(delete_files=True):
    """
    Wipes the report index. If delete_files is True, also deletes the
    actual report files from disk (not just the index entries).
    Returns the number of entries cleared.
    """

    entries = report_generator.load_report_index()

    if delete_files:
        for e in entries:
            path = e.get("filepath", "")
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    report_generator._save_report_index([])
    return len(entries)
