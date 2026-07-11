"""
SecureWin Toolkit - Report Scheduler Service

Persists "Scheduled Reports" to disk (JSON) and runs a background
thread that checks every 30s whether any enabled schedule is due,
and if so, actually calls report_generator.generate_report() for it
-- same real AuditCache-backed generation the manual "Generate Report"
button uses.

Public API used by ReportsPage:

    start_scheduler()                     -> starts the background loop (idempotent)
    load_schedules()                      -> list[dict], newest first
    add_schedule(...)                     -> new schedule dict
    update_schedule(schedule_id, **kw)    -> updated schedule dict
    delete_schedule(schedule_id)          -> None
    toggle_schedule(schedule_id, enabled) -> updated schedule dict
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
import datetime

from src.services import report_generator


SCHEDULES_PATH = os.path.join(report_generator.REPORTS_DIR, "schedules.json")

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

_scheduler_thread = None
_scheduler_lock = threading.Lock()
_stop_event = threading.Event()

# Called with (schedule, entry_or_None, error_or_None) after each auto-run attempt,
# so the UI can refresh itself. Set by ReportsPage.
on_auto_run = None


# ==========================================================
# PERSISTENCE
# ==========================================================

def load_schedules():

    if not os.path.exists(SCHEDULES_PATH):
        return []

    try:
        with open(SCHEDULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    data.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return data


def _save_schedules(schedules):
    os.makedirs(report_generator.REPORTS_DIR, exist_ok=True)
    with open(SCHEDULES_PATH, "w", encoding="utf-8") as f:
        json.dump(schedules, f, indent=2)


# ==========================================================
# NEXT-RUN CALCULATION
# ==========================================================

def _compute_next_run(frequency, day_of_week, time_str, from_dt=None):
    """
    frequency   : "Daily" | "Weekly"
    day_of_week : 0=Monday .. 6=Sunday (used only for Weekly)
    time_str    : "HH:MM" 24-hour
    """

    now = from_dt or datetime.datetime.now()
    hour, minute = map(int, time_str.split(":"))

    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

    if frequency == "Daily":
        if candidate <= now:
            candidate += datetime.timedelta(days=1)
        return candidate

    # Weekly
    days_ahead = (day_of_week - candidate.weekday()) % 7
    candidate += datetime.timedelta(days=days_ahead)
    if candidate <= now:
        candidate += datetime.timedelta(days=7)
    return candidate


def _format_schedule_str(frequency, day_of_week, time_str):
    hour, minute = map(int, time_str.split(":"))
    dt = datetime.time(hour, minute)
    time_label = dt.strftime("%I:%M %p").lstrip("0")

    if frequency == "Daily":
        return f"Every day {time_label}"
    return f"Every {WEEKDAYS[day_of_week]} {time_label}"


# ==========================================================
# CRUD
# ==========================================================

def add_schedule(name, audit_type, fmt, frequency, day_of_week, time_str, options=None):

    schedules = load_schedules()

    now = datetime.datetime.now()
    next_run = _compute_next_run(frequency, day_of_week, time_str, now)

    entry = {
        "id": uuid.uuid4().hex[:10],
        "name": name,
        "audit_type": audit_type,
        "format": fmt,
        "frequency": frequency,
        "day_of_week": day_of_week,
        "time": time_str,
        "schedule_label": _format_schedule_str(frequency, day_of_week, time_str),
        "options": options or {"include_passed": True, "include_recommendations": True, "include_system_info": True},
        "enabled": True,
        "created_at": now.isoformat(timespec="seconds"),
        "next_run": next_run.isoformat(timespec="seconds"),
        "last_run": None,
        "last_status": None,
    }

    schedules.append(entry)
    _save_schedules(schedules)
    return entry


def update_schedule(schedule_id, **fields):

    schedules = load_schedules()
    target = next((s for s in schedules if s["id"] == schedule_id), None)
    if target is None:
        raise ValueError("Schedule not found.")

    target.update(fields)

    if any(k in fields for k in ("frequency", "day_of_week", "time")):
        target["schedule_label"] = _format_schedule_str(
            target["frequency"], target["day_of_week"], target["time"]
        )
        target["next_run"] = _compute_next_run(
            target["frequency"], target["day_of_week"], target["time"]
        ).isoformat(timespec="seconds")

    _save_schedules(schedules)
    return target


def delete_schedule(schedule_id):

    schedules = load_schedules()
    schedules = [s for s in schedules if s["id"] != schedule_id]
    _save_schedules(schedules)


def toggle_schedule(schedule_id, enabled):

    fields = {"enabled": enabled}
    if enabled:
        # Re-arm: push next_run forward from now so toggling back on
        # doesn't immediately fire for a time that already passed.
        schedules = load_schedules()
        target = next((s for s in schedules if s["id"] == schedule_id), None)
        if target is not None:
            fields["next_run"] = _compute_next_run(
                target["frequency"], target["day_of_week"], target["time"]
            ).isoformat(timespec="seconds")

    return update_schedule(schedule_id, **fields)


# ==========================================================
# BACKGROUND LOOP
# ==========================================================

def start_scheduler(poll_seconds=30):
    """Idempotent: safe to call every time the Reports page is opened."""

    global _scheduler_thread

    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return

        _stop_event.clear()
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop, args=(poll_seconds,), daemon=True
        )
        _scheduler_thread.start()


def stop_scheduler():
    _stop_event.set()


def _scheduler_loop(poll_seconds):

    while not _stop_event.is_set():
        try:
            _check_due_schedules()
        except Exception:
            pass  # never let a bad schedule kill the background loop
        _stop_event.wait(poll_seconds)


def _check_due_schedules():

    schedules = load_schedules()
    now = datetime.datetime.now()
    changed = False

    for sched in schedules:
        if not sched.get("enabled"):
            continue

        try:
            next_run = datetime.datetime.fromisoformat(sched["next_run"])
        except (KeyError, ValueError):
            continue

        if next_run > now:
            continue

        # Due -- run it.
        entry = None
        error = None
        try:
            entry = report_generator.generate_report(
                sched["audit_type"], sched["format"], sched.get("options", {})
            )
            sched["last_status"] = "Completed"
        except Exception as e:
            sched["last_status"] = f"Failed: {e}"
            error = e

        sched["last_run"] = now.isoformat(timespec="seconds")
        sched["next_run"] = _compute_next_run(
            sched["frequency"], sched["day_of_week"], sched["time"], now
        ).isoformat(timespec="seconds")
        changed = True

        if on_auto_run is not None:
            try:
                on_auto_run(sched, entry, error)
            except Exception:
                pass

    if changed:
        _save_schedules(schedules)
