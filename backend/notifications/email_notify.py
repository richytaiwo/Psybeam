import os
import smtplib
from email.mime.text import MIMEText


# Get the email settings from the environment
SMTP_HOST = os.environ.get("PSYBEAM_SMTP_HOST")
SMTP_PORT = int(os.environ.get("PSYBEAM_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("PSYBEAM_SMTP_USER")
SMTP_PASSWORD = os.environ.get("PSYBEAM_SMTP_PASSWORD")

ALERT_TO = os.environ.get("PSYBEAM_ALERT_EMAIL_TO")
ALERT_FROM = os.environ.get(
    "PSYBEAM_ALERT_EMAIL_FROM",
    "psybeam@localhost"
)


def maybe_notify_email(incident: dict):
    # Don't try to send an email if email settings are missing
    if not SMTP_HOST or not ALERT_TO:
        return

    # Create the message that will be sent
    body = (
        f"Psybeam detected a critical security incident.\n\n"
        f"Rule: {incident['primary_rule']}\n"
        f"Source IP: {incident['ip']} ({incident.get('country', 'Unknown')})\n"
        f"Targeted users: "
        f"{', '.join(incident.get('targeted_users', [])) or 'n/a'}\n"
        f"Attempts: {incident['attempts']}\n"
        f"Risk score: {incident['risk_score']}/100\n"
        f"Recommended actions:\n"
        + "\n".join(
            f"  - {a}"
            for a in incident.get("recommended_actions", [])
        )
    )

    msg = MIMEText(body)

    # Set the email details
    msg["Subject"] = f"[Psybeam] Critical alert: {incident['ip']}"
    msg["From"] = ALERT_FROM
    msg["To"] = ALERT_TO

    try:
        # Connect to the email server
        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=10
        ) as server:

            # Secure the connection
            server.starttls()

            # Log in if login details were provided
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)

            # Send the alert
            server.sendmail(
                ALERT_FROM,
                [ALERT_TO],
                msg.as_string()
            )

    except Exception:
        # Don't let an email error stop Psybeam from running
        pass