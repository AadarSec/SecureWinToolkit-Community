from .powershell_utils import run_ps
import json


def check_windows_update():

    try:
        script = (
            "$Session = New-Object -ComObject Microsoft.Update.Session;"
            "$Searcher = $Session.CreateUpdateSearcher();"
            "$Result = $Searcher.Search('IsInstalled=0 and IsHidden=0');"
            "$items = foreach ($u in $Result.Updates) {"
            "  $cats = @();"
            "  foreach ($c in $u.Categories) { $cats += $c.Name };"
            "  [PSCustomObject]@{"
            "    Title = $u.Title;"
            "    Categories = ($cats -join '|');"
            "    IsMandatory = $u.IsMandatory"
            "  } | ConvertTo-Json -Compress"
            "};"
            "'[' + ($items -join ',') + ']'"
        )

        result = run_ps(script, timeout=90)

        output = result.stdout

        if not output:
            output = "[]"

        try:
            items = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            items = []

        quality_updates = 0
        defender_updates = 0
        driver_updates = 0
        optional_updates = 0
        updates_list = []

        for item in items:

            title = item.get("Title", "Unknown update")

            categories_raw = item.get("Categories", "") or ""

            categories = [c.lower() for c in categories_raw.split("|") if c]

            is_mandatory = item.get("IsMandatory", True)

            updates_list.append(title)

            if "definition" in " ".join(categories) or "defender" in title.lower():
                defender_updates += 1

            elif "driver" in " ".join(categories):
                driver_updates += 1

            elif is_mandatory is False:
                optional_updates += 1

            else:
                quality_updates += 1

        pending_total = len(items)

        if pending_total == 0:
            return {
                "status": "Passed",
                "risk": "Low",
                "details": "Windows is fully up to date. No pending updates were found.",
                "recommendation": "No action needed.",
                "quality_updates": 0,
                "defender_updates": 0,
                "driver_updates": 0,
                "optional_updates": 0,
                "updates": []
            }

        if quality_updates > 0:
            return {
                "status": "Critical",
                "risk": "High",
                "details": f"{pending_total} update(s) pending, including {quality_updates} "
                           f"quality/security update(s) that address known vulnerabilities.",
                "recommendation": "Install pending quality/security updates as soon as possible "
                                   "via Windows Update settings.",
                "quality_updates": quality_updates,
                "defender_updates": defender_updates,
                "driver_updates": driver_updates,
                "optional_updates": optional_updates,
                "updates": updates_list
            }

        return {
            "status": "Warning",
            "risk": "Medium",
            "details": f"{pending_total} update(s) pending (Defender/driver/optional).",
            "recommendation": "Install pending updates when convenient to keep protections current.",
            "quality_updates": quality_updates,
            "defender_updates": defender_updates,
            "driver_updates": driver_updates,
            "optional_updates": optional_updates,
            "updates": updates_list
        }

    except Exception as e:
        return {
            "status": "Warning",
            "risk": "Unknown",
            "details": f"Windows Update check failed: {e}",
            "recommendation": "Open Windows Update settings manually to check for updates.",
            "quality_updates": 0,
            "defender_updates": 0,
            "driver_updates": 0,
            "optional_updates": 0,
            "updates": []
        }
