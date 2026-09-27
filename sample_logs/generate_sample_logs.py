import random
from datetime import datetime, timedelta

random.seed(42)

HOSTNAME = "prod-web01"
USERS = ["admin", "root", "deploy", "jsmith", "mchen", "svc-backup", "ops"]
TRUSTED_IPS = ["10.0.0.5", "10.0.0.12", "10.0.0.23", "192.168.1.50"]
ATTACKER_IPS = ["185.220.101.47", "45.155.205.233", "194.26.29.156", "103.94.4.31"]

# Start date for the sample logs
start = datetime(2026, 9, 20, 0, 0, 0)

lines = []
pid = 10000


def fmt(ts):
    # Format the timestamp to look like a real syslog entry
    return ts.strftime("%b %d %H:%M:%S")


def log(ts, msg):
    global pid

    # Add a new log entry with a unique process ID
    lines.append(f"{fmt(ts)} {HOSTNAME} sshd[{pid}]: {msg}")
    pid += 1


# Create normal login activity across 7 days
cur = start

for day in range(7):
    day_start = start + timedelta(days=day)

    for _ in range(60):
        # Most normal activity happens during the day
        hour = random.randint(8, 19)

        ts = day_start + timedelta(
            hours=hour,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )

        user = random.choice(USERS[3:])
        ip = random.choice(TRUSTED_IPS)
        port = random.randint(30000, 60000)

        # Add a small number of failed logins to make the data more realistic
        if random.random() < 0.08:
            log(
                ts,
                f"Failed password for {user} from {ip} port {port} ssh2"
            )
        else:
            log(
                ts,
                f"Accepted password for {user} from {ip} port {port} ssh2"
            )


# Create a brute force attack against the admin account
burst_start = start + timedelta(days=1, hours=3, minutes=22)

ip = ATTACKER_IPS[0]

for i in range(37):
    ts = burst_start + timedelta(seconds=i * 7)
    port = random.randint(30000, 60000)

    log(
        ts,
        f"Failed password for admin from {ip} port {port} ssh2"
    )


# Create another brute force attack against the root account
burst_start = start + timedelta(days=3, hours=2, minutes=10)

ip = ATTACKER_IPS[1]

for i in range(52):
    ts = burst_start + timedelta(seconds=i * 4)
    port = random.randint(30000, 60000)

    log(
        ts,
        f"Failed password for root from {ip} port {port} ssh2"
    )


# Create a credential stuffing attack using many different usernames
burst_start = start + timedelta(days=4, hours=4, minutes=5)

ip = ATTACKER_IPS[2]

candidate_users = USERS + [
    "oracle",
    "postgres",
    "test",
    "guest",
    "user",
    "administrator",
    "www-data",
    "git",
    "ubuntu"
]

for i, user in enumerate(candidate_users * 2):
    ts = burst_start + timedelta(seconds=i * 11)
    port = random.randint(30000, 60000)

    if user in USERS:
        log(
            ts,
            f"Invalid user {user} from {ip} port {port}"
        )
    else:
        log(
            ts,
            f"Failed password for invalid user {user} from {ip} port {port} ssh2"
        )


# Create a slower brute force attack against the deploy account
burst_start = start + timedelta(days=5, hours=1, minutes=40)

ip = ATTACKER_IPS[3]

for i in range(15):
    ts = burst_start + timedelta(seconds=i * 25)
    port = random.randint(30000, 60000)

    log(
        ts,
        f"Failed password for deploy from {ip} port {port} ssh2"
    )


# Add a successful login after the failed attempts
# This can be picked up as a possible account compromise
log(
    burst_start + timedelta(seconds=15 * 25 + 30),
    f"Accepted password for deploy from {ip} port {random.randint(30000, 60000)} ssh2"
)


# Add some logins at unusual hours
odd_ips = ["203.0.113.9", "198.51.100.23", "91.219.237.7"]

for day in range(6):
    for _ in range(random.randint(1, 3)):
        ts = start + timedelta(
            days=day,
            hours=random.randint(2, 5),
            minutes=random.randint(0, 59)
        )

        user = random.choice(USERS)
        ip = random.choice(odd_ips)
        port = random.randint(30000, 60000)

        # Have a mix of successful and failed unusual logins
        outcome = random.choice(["Failed", "Failed", "Accepted"])

        log(
            ts,
            f"{outcome} password for {user} from {ip} port {port} ssh2"
        )


# Sort all log entries by their timestamp
def sort_key(line):
    ts_str = " ".join(line.split()[0:3])
    return datetime.strptime(
        f"2026 {ts_str}",
        "%Y %b %d %H:%M:%S"
    )


lines.sort(key=sort_key)


# Save the generated logs to a file
with open("auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")


print(f"Wrote {len(lines)} log lines to auth.log")