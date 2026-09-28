from collections import defaultdict
import pandas as pd

from .geoip import enrich_ip


# How many points each detection rule adds
RULE_WEIGHTS = {
    "brute_force": 35,
    "credential_stuffing": 30,
    "odd_hours": 10,
    "compromise_suspected": 50,
}


# Actions that can be suggested for each type of incident
RECOMMENDED_ACTIONS = {
    "brute_force": [
        "Temporarily block source IP",
        "Review authentication logs for the targeted account",
        "Enable rate limiting / fail2ban on the affected service",
    ],
    "credential_stuffing": [
        "Block source IP at the firewall/WAF",
        "Force password reset for any targeted accounts that exist",
        "Enable MFA if not already required",
    ],
    "odd_hours": [
        "Confirm the activity with the account owner",
        "Review VPN/geofencing policy for after-hours access",
    ],
    "compromise_suspected": [
        "Reset credentials for the affected account immediately",
        "Terminate active sessions for the account",
        "Review recent activity performed by the account for lateral movement",
        "Escalate to on-call security responder",
    ],
}


def severity_for_score(score: float) -> str:
    # Turn the risk score into a severity level
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    else:
        return "low"

    return "informational"

def build_incidents(signals: list[dict], anomaly_df: pd.DataFrame) -> list[dict]:

    # Group all signals by IP address
    by_ip = defaultdict(list)

    for sig in signals:
        by_ip[sig["ip"]].append(sig)

    # Create a quick lookup for anomaly scores
    anomaly_lookup = {}

    if anomaly_df is not None and not anomaly_df.empty:
        anomaly_lookup = (
            anomaly_df
            .set_index("ip")["anomaly_score"]
            .to_dict()
        )

    incidents = []

    # Build one incident for each IP
    for ip, sigs in by_ip.items():
        score = 0.0
        rules_hit = set()
        targeted_users = set()
        max_count = 0

        # Find when the incident started and ended
        earliest = min(s["window_start"] for s in sigs)
        latest = max(s["window_end"] for s in sigs)

        for s in sigs:
            rules_hit.add(s["rule"])

            # Keep track of the accounts being targeted
            if s["user"]:
                targeted_users.add(s["user"])

            max_count = max(max_count, s["count"])

            # Add the points for the rule
            weight = RULE_WEIGHTS.get(s["rule"], 5)

            # Add a small bonus for larger attacks
            bonus = min(s["count"] - 1, 20) * 0.5

            score += weight + bonus

        # Get location information for the IP
        geo = enrich_ip(ip)

        # Add extra points for flagged regions
        if geo["flagged_region"]:
            score += 10

        # Add part of the machine learning score
        anomaly_score = anomaly_lookup.get(ip, 0.0)
        score += 0.25 * anomaly_score

        # Keep the final score between 0 and 100
        score = round(min(score, 100), 1)

        # Work out the severity
        severity = severity_for_score(score)

        # Find the most important rule that was triggered
        primary_rule = max(
            rules_hit,
            key=lambda r: RULE_WEIGHTS.get(r, 0)
        )

        # Get the recommended actions for that rule
        actions = RECOMMENDED_ACTIONS.get(
            primary_rule,
            ["Review activity manually"]
        )

        # Calculate how long the incident lasted
        duration = (latest - earliest).total_seconds()

        incidents.append({
            "ip": ip,
            "country": geo["country"],
            "is_internal": geo["is_internal"],
            "rules_hit": sorted(rules_hit),
            "primary_rule": primary_rule,
            "targeted_users": sorted(targeted_users),
            "attempts": max_count,
            "window_start": earliest,
            "window_end": latest,
            "duration_seconds": duration,
            "anomaly_score": anomaly_score,
            "risk_score": score,
            "severity": severity,
            "recommended_actions": actions,
            "detail": "; ".join(
                s["detail"] for s in sigs[:3]
            ),
        })

    # Show the highest risk incidents first
    incidents.sort(
        key=lambda i: i["risk_score"],
        reverse=True
    )

    return incidents


def overall_threat_level(incidents: list[dict]) -> str:
    # No incidents means the system is currently low risk
    if not incidents:
        return "LOW"

    # Look at the highest risk incident
    top = incidents[0]["risk_score"]

    # Count critical incidents
    critical_count = sum(
        1 for i in incidents
        if i["severity"] == "critical"
    )

    if critical_count >= 1 or top >= 75:
        return "CRITICAL" if critical_count >= 2 else "HIGH"

    if top >= 50:
        return "MEDIUM"

    return "LOW"