# Psybeam

Psybeam is a security monitoring and log analysis tool I built to explore how authentication logs can be used to detect suspicious activity.

It takes SSH and authentication logs, processes them into structured events, looks for patterns that could indicate an attack, and displays the results through a SOC style dashboard.

The main idea was to combine Python, data analysis, machine learning and cybersecurity into one project rather than building a simple security script.

## Features

* SSH authentication log parsing
* Brute force detection
* Credential stuffing detection
* Odd hour login detection
* Detection of successful logins after repeated failures
* IP based anomaly detection using Isolation Forest
* Risk scoring from 0 to 100
* Incident severity levels
* Offline IP and country enrichment
* SQLite database for storing analysis results
* FastAPI backend
* SOC style web dashboard
* Log file upload
* Sample authentication logs for testing
* Discord alerts for critical incidents
* Docker and Docker Compose support
* Automated tests with pytest

## How It Works

Psybeam follows a simple analysis pipeline:

```text
Authentication Log
        |
        v
    Log Parser
        |
        v
 Structured Events
        |
        +------------------+
        |                  |
        v                  v
 Rule Detection       Anomaly Detection
        |                  |
        +--------+---------+
                 |
                 v
           Risk Scoring
                 |
                 v
             Incidents
                 |
        +--------+--------+
        |                 |
        v                 v
     SQLite          Dashboard
```

The rule based detection looks for known patterns such as repeated failed logins, attempts against multiple usernames and logins outside normal hours.

The machine learning side uses Isolation Forest to look for IP addresses with unusual behaviour based on features such as failed login ratio, number of users, number of events and activity during night hours.

These results are combined into a risk score which is then used to assign an incident severity.

## Detection Rules

### Brute Force

Detects repeated failed login attempts against the same username from the same IP within a short period.

### Credential Stuffing

Detects an IP attempting to log in using multiple different usernames in a short period.

### Odd Hour Activity

Flags authentication activity outside normal working hours.

### Successful Login After Failures

Looks for a successful login shortly after several failed attempts from the same IP. This is treated as a higher risk pattern because it could indicate that an account has been compromised.

## Machine Learning

Psybeam uses `IsolationForest` from scikit-learn for anomaly detection.

Each IP address is converted into a set of features:

* Total events
* Failed login ratio
* Number of different usernames
* Number of different ports
* Average login hour
* Night activity ratio
* Peak events per minute
* Whether the IP is internal

The model produces an anomaly score which is combined with the rule based detections when calculating the final risk score.

This is not intended to replace a real SIEM or production security monitoring system. The machine learning component is mainly used to explore how anomaly detection can be combined with traditional security rules.

## Dashboard

The dashboard provides an overview of the analysis, including:

* System status
* Overall threat level
* Number of events analysed
* Suspicious events
* Critical alerts
* Latest incident
* Severity distribution
* Attack frequency over time
* Failed vs successful logins
* Top attacking IP addresses
* Affected accounts
* Full incident log

## Technologies

### Backend

* Python
* FastAPI
* Pandas
* NumPy
* scikit-learn
* SQLAlchemy
* SQLite
* HTTPX

### Frontend

* HTML
* CSS
* JavaScript
* Plotly.js

### Testing

* pytest

### Deployment

* Docker
* Docker Compose
* Nginx

## Project Structure

```text
Psybeam/
│
├── backend/
│   ├── database/
│   ├── detection/
│   ├── notifications/
│   ├── parsers/
│   ├── config.py
│   └── main.py
│
├── frontend/
│   └── dashboard/
│       ├── index.html
│       └── style.css
│
├── sample_logs/
│   ├── auth.log
│   └── generate_sample_logs.py
│
├── tests/
│
├── docker/
│   ├── Dockerfile.backend
│   └── Dockerfile.frontend
│
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Running Locally

### 1. Clone the repository

```bash
git clone https://github.com/richytaiwo/Psybeam.git
cd Psybeam
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install the dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the backend

```bash
uvicorn backend.main:app --reload
```

The API will be available at:

```text
http://localhost:8000
```

### 5. Open the dashboard

Open:

```text
frontend/dashboard/index.html
```

The dashboard connects to the FastAPI backend running on port 8000.

## Running With Docker

Psybeam can also be run using Docker Compose.

```bash
docker compose up --build
```

The dashboard will be available at:

```text
http://localhost:8080
```

The API will be available at:

```text
http://localhost:8000
```

To stop the containers:

```bash
docker compose down
```

The SQLite database is stored in a Docker volume so analysis data is kept between container restarts.

## Sample Data

The project includes a sample SSH authentication log containing a mixture of normal activity and simulated suspicious behaviour.

The sample data includes:

* Normal business hour logins
* Brute force attacks
* Credential stuffing
* Odd hour logins
* A successful login following repeated failures

This makes it possible to demonstrate the detection pipeline without needing a real authentication log.

## Testing

The project includes tests for the detection and risk scoring components.

Run the tests with:

```bash
pytest
```

The tests cover areas such as:

* Brute force detection
* Credential stuffing detection
* Odd hour detection
* Successful logins following failures
* Anomaly detection
* Risk scoring
* Incident grouping

## API

Some of the main endpoints are:

```text
POST /api/analyze/sample
POST /api/analyze/upload

GET /api/stats
GET /api/runs
GET /api/incidents
GET /api/incidents/latest

GET /api/severity-distribution
GET /api/top-ips
GET /api/failed-vs-success
GET /api/timeline
GET /api/affected-accounts

GET /api/health
```

FastAPI also provides interactive API documentation at:

```text
http://localhost:8000/docs
```

## Alerts

Psybeam can send critical incident alerts to Discord using a Discord webhook.

Set the following environment variable before starting the backend:

```text
PSYBEAM_DISCORD_WEBHOOK_URL
```

The alert includes information such as the detected rule, source IP, targeted account, number of attempts and risk score.

## Limitations

Psybeam is a portfolio and learning project rather than a production security monitoring system.

The included IP country lookup uses a small offline prefix table rather than a full commercial GeoIP database.

The anomaly detection model also works from the data available in the current analysis rather than a large historical training dataset.

The sample authentication logs are simulated and should not be treated as real attack data.

## Future Improvements

Some areas I would like to improve in the future include:

* Support for more log formats
* A proper GeoIP database
* More detection rules
* Historical anomaly baselines
* More detailed incident investigation
* Authentication account behaviour tracking
* Better alert configuration
* User authentication for the dashboard
* Deployment to a hosted environment

## Purpose

I built Psybeam as a way to combine areas I have been learning in Data Science and AI with an interest in cybersecurity.

The project gave me experience working with Python, APIs, databases, machine learning, data processing, testing and Docker while building something that has a practical use case.

## Author

Richard Taiwo

BSc Data Science and Artificial Intelligence
Technological University Dublin

[GitHub](https://github.com/richytaiwo)
