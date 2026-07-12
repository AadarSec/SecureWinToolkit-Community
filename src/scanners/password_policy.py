from .powershell_utils import run_cmd


def _get_value(output, key):
    """
    Extract the value after ':' from net accounts output.
    """

    for line in output.splitlines():

        if key.lower() in line.lower():

            if ":" in line:
                return line.split(":", 1)[1].strip()

    return "Unknown"


def _format_unit(value, unit):
    """
    Don't append units to 'Never'.
    """

    if value.lower() == "never":
        return value

    return f"{value} {unit}"


def check_password_policy():

    try:

        result = run_cmd(["net", "accounts"], timeout=20)

        output = result.stdout

        if not output.strip():

            return {
                "status": "Warning",
                "risk": "Unknown",
                "details": "Unable to retrieve password policy.",
                "recommendation": "Verify password policy manually.",
                "detection_method": "net accounts",
                "confidence": "0%"
            }

        minimum_length = _get_value(output, "Minimum password length")
        maximum_age = _get_value(output, "Maximum password age")
        minimum_age = _get_value(output, "Minimum password age")
        password_history = _get_value(
            output,
            "Length of password history maintained"
        )

        lockout_threshold = _get_value(output, "Lockout threshold")
        lockout_duration = _get_value(output, "Lockout duration")
        lockout_window = _get_value(output, "Lockout observation window")

        findings = []

        recommendation_items = []

        # -----------------------------
        # Minimum Password Length
        # -----------------------------

        try:

            length = int(minimum_length)

            if length < 8:

                findings.append(
                    f"Minimum password length is {length}. Recommended minimum is 8 characters."
                )

                recommendation_items.append(
                    "Increase the minimum password length."
                )

        except Exception:
            pass

        # -----------------------------
        # Password History
        # -----------------------------

        try:

            if password_history.lower() == "none":
                history = 0
            else:
                history = int(password_history)

            if history < 5:

                findings.append(
                    "Password history is weak."
                )

                recommendation_items.append(
                    "Configure password history to prevent password reuse."
                )

        except Exception:
            pass

        # -----------------------------
        # Maximum Password Age
        # -----------------------------

        try:

            if maximum_age.lower() != "unlimited":

                max_age = int(maximum_age)

                if max_age > 90:

                    findings.append(
                        "Maximum password age exceeds the recommended value."
                    )

                    recommendation_items.append(
                        "Reduce the maximum password age."
                    )

        except Exception:
            pass

        # -----------------------------
        # Final Result
        # -----------------------------

        if findings:

            status = "Warning"

            if len(findings) >= 2:
                risk = "High"
            else:
                risk = "Medium"

            details = "\n".join(findings)

            recommendation = "\n".join(
                f"• {item}" for item in recommendation_items
            )

        else:

            status = "Passed"
            risk = "Low"

            details = (
                "Password policy meets the recommended baseline."
            )

            recommendation = "No action required."

        details += (

            "\n\n"

            "Password Policy\n"
            "-------------------------\n"

            f"Minimum Password Length : {minimum_length}\n"
            f"Maximum Password Age    : {_format_unit(maximum_age, 'Days')}\n"
            f"Minimum Password Age    : {_format_unit(minimum_age, 'Days')}\n"
            f"Password History        : {password_history}\n\n"

            "Account Lockout\n"
            "-------------------------\n"

            f"Lockout Threshold       : {lockout_threshold}\n"
            f"Lockout Duration        : {_format_unit(lockout_duration, 'Minutes')}\n"
            f"Observation Window      : {_format_unit(lockout_window, 'Minutes')}"
        )

        return {

            "status": status,
            "risk": risk,
            "details": details,
            "recommendation": recommendation,
            "detection_method": "net accounts",
            "confidence": "100%"
        }

    except Exception as e:

        return {

            "status": "Warning",
            "risk": "Unknown",
            "details": f"Password policy check failed: {e}",
            "recommendation": "Verify password policy manually.",
            "detection_method": "net accounts",
            "confidence": "0%"
        }