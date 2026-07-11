"""
SecureWin Toolkit - Report Generator Service

Turns whatever is currently sitting in AuditCache (real scan results,
produced by WindowsAudit / NetworkAudit) into an actual report file on
disk, and keeps a small JSON index so the Reports page can show real
"Recent Reports" + real stat cards instead of placeholder data.

Public API used by ReportsPage:

    generate_report(audit_type, fmt, options)   -> report dict (raises on failure)
    load_report_index()                         -> list[dict]  (newest first)
    get_report_stats()                          -> dict
    open_report(report_id)                      -> None (opens file w/ OS default app)
"""

from __future__ import annotations

import csv
import io
import json
import os
import platform
import subprocess
import datetime

from src.core.audit_cache import AuditCache


# ==========================================================
# PATHS
# ==========================================================

REPORTS_DIR = os.path.join(os.path.expanduser("~"), "SecureWinToolkit", "Reports")
INDEX_PATH = os.path.join(REPORTS_DIR, "index.json")

os.makedirs(REPORTS_DIR, exist_ok=True)


# ==========================================================
# INDEX (persistent "database" of generated reports)
# ==========================================================

def load_report_index():
    """Returns all generated reports, newest first."""

    if not os.path.exists(INDEX_PATH):
        return []

    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    data.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return data


def _save_report_index(entries):
    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def _add_to_index(entry):
    entries = load_report_index()
    entries.append(entry)
    _save_report_index(entries)
    return entries


# ==========================================================
# STATS (used by the top 4 stat cards)
# ==========================================================

def get_report_stats():

    entries = load_report_index()

    now = datetime.datetime.now()
    cutoff = now - datetime.timedelta(days=30)

    def _within_30_days(entry):
        try:
            ts = datetime.datetime.fromisoformat(entry["timestamp"])
        except (KeyError, ValueError):
            return False
        return ts >= cutoff

    windows_count = sum(
        1 for e in entries
        if e.get("audit_type") == "windows" and _within_30_days(e)
    )
    network_count = sum(
        1 for e in entries
        if e.get("audit_type") == "network" and _within_30_days(e)
    )

    if entries:
        latest = entries[0]
        last_date = latest.get("date", "-")
        last_time = latest.get("time", "-")
    else:
        last_date = "-"
        last_time = "No reports yet"

    return {
        "total_reports": len(entries),
        "windows_reports": windows_count,
        "network_reports": network_count,
        "last_report_date": last_date,
        "last_report_time": last_time,
    }


# ==========================================================
# DATA COLLECTION (pulls real results out of AuditCache)
# ==========================================================

def _collect_results(audit_type):
    """
    Returns (results_dict, human_label) for the requested audit type,
    sourced from AuditCache -- i.e. whatever the user actually scanned.
    """

    if audit_type == "windows":
        results = AuditCache.get_windows_results()
        label = "Windows Audit Report"
    elif audit_type == "network":
        results = AuditCache.get_network_results()
        label = "Network Audit Report"
    else:
        raise ValueError(f"Unknown audit type: {audit_type}")

    if not results:
        raise ValueError(
            f"No {label.replace(' Report', '')} results found. "
            f"Run a scan first, then generate the report."
        )

    return results, label


def _filter_results(results, options):
    """Applies the Report Options checkboxes to the raw scan results."""

    include_passed = options.get("include_passed", True)

    filtered = {}
    for name, result in results.items():
        status = result.get("status", "")
        if status == "Passed" and not include_passed:
            continue
        filtered[name] = result

    return filtered


# ==========================================================
# MAIN ENTRY POINT
# ==========================================================

def generate_report(audit_type, fmt, options=None):
    """
    Generates a report file from live AuditCache data.

    audit_type : "windows" | "network"
    fmt        : "PDF" | "HTML" | "CSV" | "JSON"
    options    : {
        "include_passed": bool,
        "include_recommendations": bool,
        "include_system_info": bool,
        "executive_summary_only": bool,
    }

    Returns the index entry dict for the newly created report.
    Raises ValueError if there's nothing to report on.
    """

    options = options or {}

    results, label = _collect_results(audit_type)
    filtered = _filter_results(results, options)

    now = datetime.datetime.now()
    timestamp_slug = now.strftime("%Y%m%d_%H%M%S")
    filename = f"{audit_type}_audit_{timestamp_slug}.{fmt.lower()}"
    filepath = os.path.join(REPORTS_DIR, filename)

    if fmt == "JSON":
        _write_json(filepath, filtered, options)
    elif fmt == "CSV":
        _write_csv(filepath, filtered)
    elif fmt == "HTML":
        _write_html(filepath, filtered, label, options, now)
    elif fmt == "PDF":
        _write_pdf(filepath, filtered, label, options, now)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    size_bytes = os.path.getsize(filepath)
    size_str = _human_size(size_bytes)

    entry = {
        "id": timestamp_slug,
        "name": label,
        "type": fmt,
        "audit_type": audit_type,
        "date": now.strftime("%d %b %Y"),
        "time": now.strftime("%I:%M %p").lstrip("0"),
        "timestamp": now.isoformat(timespec="seconds"),
        "size": size_str,
        "status": "Completed",
        "filepath": filepath,
        "check_count": len(filtered),
    }

    _add_to_index(entry)
    return entry


# ==========================================================
# FORMAT WRITERS
# ==========================================================

def _write_json(filepath, results, options):

    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "options": options,
        "checks": results,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _write_csv(filepath, results):

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Check", "Status", "Risk", "Details", "Recommendation"])

        for name, r in results.items():
            writer.writerow([
                name,
                r.get("status", ""),
                r.get("risk", ""),
                r.get("details", ""),
                r.get("recommendation", ""),
            ])


_STATUS_COLORS = {
    "Passed": "#22C55E",
    "Warning": "#F59E0B",
    "Critical": "#B91C1C",
    "Information": "#4EA8FF",
}


def _write_html(filepath, results, label, options, now):

    rows = []
    for name, r in results.items():
        status = r.get("status", "Unknown")
        color = _STATUS_COLORS.get(status, "#9CA3AF")

        recommendation_html = ""
        if options.get("include_recommendations", True) and r.get("recommendation"):
            recommendation_html = f"<div class='rec'>Recommendation: {_escape(r.get('recommendation'))}</div>"

        rows.append(f"""
        <tr>
            <td>{_escape(name)}</td>
            <td><span class="badge" style="background:{color}22;color:{color}">{_escape(status)}</span></td>
            <td>{_escape(str(r.get('risk', '-')))}</td>
            <td>{_escape(str(r.get('details', '-')))}{recommendation_html}</td>
        </tr>""")

    passed = sum(1 for r in results.values() if r.get("status") == "Passed")
    warnings = sum(1 for r in results.values() if r.get("status") == "Warning")
    critical = sum(1 for r in results.values() if r.get("status") == "Critical")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{_escape(label)}</title>
<style>
body {{ background:#141414; color:#F5F5F5; font-family: Segoe UI, sans-serif; padding: 30px; }}
h1 {{ color:#B91C1C; }}
.meta {{ color:#9CA3AF; margin-bottom: 20px; }}
.summary {{ display:flex; gap:16px; margin-bottom: 24px; }}
.summary div {{ background:#1E1E1E; border:1px solid #2A2A2A; border-radius:8px; padding:12px 18px; }}
table {{ width:100%; border-collapse: collapse; background:#1E1E1E; border-radius:8px; overflow:hidden; }}
th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #2A2A2A; font-size:13px; vertical-align:top; }}
th {{ color:#9CA3AF; text-transform:uppercase; font-size:11px; }}
.badge {{ padding:3px 10px; border-radius:10px; font-size:11px; font-weight:bold; }}
.rec {{ color:#9CA3AF; font-size:12px; margin-top:4px; }}
</style></head>
<body>
<h1>{_escape(label)}</h1>
<div class="meta">Generated {now.strftime('%d %b %Y, %I:%M %p')}</div>
<div class="summary">
    <div><b>{len(results)}</b><br>Total Checks</div>
    <div><b style="color:#22C55E">{passed}</b><br>Passed</div>
    <div><b style="color:#F59E0B">{warnings}</b><br>Warnings</div>
    <div><b style="color:#B91C1C">{critical}</b><br>Critical</div>
</div>
<table>
<tr><th>Check</th><th>Status</th><th>Risk</th><th>Details</th></tr>
{''.join(rows)}
</table>
</body></html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


def _write_pdf(filepath, results, label, options, now):
    """
    Uses reportlab if available (proper PDF). Falls back to a minimal
    hand-rolled single-page PDF (no external dependency) so report
    generation never hard-fails just because reportlab isn't installed.
    """

    try:
        _write_pdf_reportlab(filepath, results, label, options, now)
    except ImportError:
        _write_pdf_minimal(filepath, results, label, options, now)


def _write_pdf_reportlab(filepath, results, label, options, now):

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    )

    include_recommendations = options.get("include_recommendations", True)

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        filepath, pagesize=landscape(A4),
        topMargin=15 * mm, bottomMargin=15 * mm,
        leftMargin=15 * mm, rightMargin=15 * mm,
    )

    story = [
        Paragraph(label, styles["Title"]),
        Paragraph(f"Generated {now.strftime('%d %b %Y, %I:%M %p')}", styles["Normal"]),
        Spacer(1, 12),
    ]

    if include_recommendations:
        header = ["Check", "Status", "Risk", "Details", "Recommendation"]
        col_widths = [95, 50, 45, 210, 210]
    else:
        header = ["Check", "Status", "Risk", "Details"]
        col_widths = [110, 60, 55, 350]

    table_data = [header]
    for name, r in results.items():
        row = [
            name,
            r.get("status", ""),
            str(r.get("risk", "-")),
            Paragraph(str(r.get("details", "-")), styles["Normal"]),
        ]
        if include_recommendations:
            row.append(Paragraph(str(r.get("recommendation", "-")), styles["Normal"]))
        table_data.append(row)

    status_colors = {
        "Passed": colors.HexColor("#22C55E"),
        "Warning": colors.HexColor("#F59E0B"),
        "Critical": colors.HexColor("#B91C1C"),
        "Information": colors.HexColor("#4EA8FF"),
    }

    table = Table(table_data, colWidths=col_widths)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E1E1E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#2A2A2A")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, (name, r) in enumerate(results.items(), start=1):
        c = status_colors.get(r.get("status", ""), colors.grey)
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), c))

    table.setStyle(TableStyle(style_cmds))
    story.append(table)

    doc.build(story)


def _write_pdf_minimal(filepath, results, options, now):
    """
    Zero-dependency fallback: writes a very simple valid single-page PDF
    listing check name / status / risk / recommendation as plain text.
    Used only if reportlab isn't installed on the machine.
    """

    include_recommendations = options.get("include_recommendations", True)

    lines = [f"{now.strftime('%d %b %Y %I:%M %p')}", ""]
    for name, r in results.items():
        lines.append(f"{name} - {r.get('status', '')} - Risk: {r.get('risk', '-')}")
        if include_recommendations and r.get("recommendation"):
            lines.append(f"   Recommendation: {r.get('recommendation')}")

    def esc(s):
        return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

    content_stream = "BT /F1 10 Tf 40 800 Td 14 TL\n"
    for line in lines:
        content_stream += f"({esc(line)}) Tj T*\n"
    content_stream += "ET"

    objects = []
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    objects.append("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        "/MediaBox [0 0 595 842] /Contents 5 0 R >>"
    )
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    stream_bytes = content_stream.encode("latin-1", errors="replace")
    objects.append(
        f"<< /Length {len(stream_bytes)} >>\nstream\n{content_stream}\nendstream"
    )

    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(buf.tell())
        buf.write(f"{i} 0 obj\n{obj}\nendobj\n".encode("latin-1", errors="replace"))

    xref_start = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode())
    buf.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.write(f"{off:010d} 00000 n \n".encode())
    buf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_start}\n%%EOF".encode()
    )

    with open(filepath, "wb") as f:
        f.write(buf.getvalue())


def _escape(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _human_size(num_bytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


# ==========================================================
# OPEN / REVEAL A GENERATED REPORT
# ==========================================================

def open_report(report_id):
    """Opens the report file with the OS default application."""

    entries = load_report_index()
    entry = next((e for e in entries if e["id"] == report_id), None)

    if entry is None or not os.path.exists(entry["filepath"]):
        raise FileNotFoundError("Report file not found on disk.")

    filepath = entry["filepath"]
    system = platform.system()

    if system == "Windows":
        os.startfile(filepath)  # noqa: this file only ever runs on Windows in prod
    elif system == "Darwin":
        subprocess.Popen(["open", filepath])
    else:
        subprocess.Popen(["xdg-open", filepath])


def reveal_report(report_id):
    """Opens the containing folder (used for 'Download' -> show in folder)."""

    entries = load_report_index()
    entry = next((e for e in entries if e["id"] == report_id), None)

    if entry is None or not os.path.exists(entry["filepath"]):
        raise FileNotFoundError("Report file not found on disk.")

    filepath = entry["filepath"]
    system = platform.system()

    if system == "Windows":
        subprocess.Popen(f'explorer /select,"{filepath}"')
    elif system == "Darwin":
        subprocess.Popen(["open", "-R", filepath])
    else:
        subprocess.Popen(["xdg-open", os.path.dirname(filepath)])
