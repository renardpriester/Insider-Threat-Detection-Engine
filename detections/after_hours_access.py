import json
from datetime import datetime

from risk_engine.scoring import (
    calculate_risk,
    classify_severity
)

AFTER_HOUR_START = 22
AFTER_HOUR_END = 6


def load_logs():
    with open("logs/mock_logs.json", "r") as f:
        return json.load(f)


def detect_after_hours_access(logs):

    alerts = []

    for log in logs:

        timestamp = datetime.fromisoformat(
            log["timestamp"]
        )

        hour = timestamp.hour

        if hour >= AFTER_HOUR_START or hour < AFTER_HOUR_END:

         risk_score = calculate_risk(
        "after_hours_access"
    )

    alert = {
        "user": log["user"],
        "alert_type": "After Hours Access",
        "location": log["location"],
        "timestamp": log["timestamp"],
        "risk_score": risk_score,
        "severity": classify_severity(risk_score)
    }

    alerts.append(alert)
    return alerts


if __name__ == "__main__":

    logs = load_logs()

    alerts = detect_after_hours_access(logs)

    print("\n=== After Hours Access Alerts ===\n")

    for alert in alerts:
        print(alert)