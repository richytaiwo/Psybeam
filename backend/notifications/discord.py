import os
import httpx

# Get the Discord webhook from the environment
WEBHOOK_URL = os.environ.get("PSYBEAM_DISCORD_WEBHOOK_URL")


def maybe_notify_discord(incident: dict):
    # Don't send anything if no webhook is set
    if not WEBHOOK_URL:
        return

    # Create the message for Discord
    content = (
        f"**Psybeam Critical Alert**\n"
        f"Rule: `{incident['primary_rule']}`\n"
        f"Source IP: `{incident['ip']}` "
        f"({incident.get('country', 'Unknown')})\n"
        f"Targeted: "
        f"{', '.join(incident.get('targeted_users', [])) or 'n/a'}\n"
        f"Attempts: {incident['attempts']}\n"
        f"Risk score: {incident['risk_score']}/100\n"
    )

    try:
        # Send the alert to Discord
        httpx.post(
            WEBHOOK_URL,
            json={"content": content},
            timeout=5.0
        )

    except Exception:
        # Don't let a Discord error stop Psybeam
        pass