import json
from collections import defaultdict
from datetime import datetime

from risk_engine.scoring import (
    calculate_risk,
    classify_severity
)

TIME_THRESHOLD_MINUTES = 60


def load_logs():
    with open("logs/mock_logs.json", "r") as f:
        return json.load(f)


def detect_impossible_travel(logs):

    user_activity = defaultdict(list)
    alerts = []

    # Organize logs by user
    for log in logs:
        user_activity[log["user"]].append(log)

    # Analyze user activity
    for user, events in user_activity.items():

        # Sort by timestamp
        events.sort(
            key=lambda x: datetime.fromisoformat(
                x["timestamp"]
            )
        )

        for i in range(len(events) - 1):

            current_event = events[i]
            next_event = events[i + 1]

            current_time = datetime.fromisoformat(
                current_event["timestamp"]
            )

            next_time = datetime.fromisoformat(
                next_event["timestamp"]
            )

            time_difference = (
                next_time - current_time
            ).total_seconds() / 60

            if (
                current_event["location"]
                != next_event["location"]
                and time_difference
                < TIME_THRESHOLD_MINUTES
            ):

                risk_score = calculate_risk(
                    "impossible_travel"
                )

                alert = {
                    "user": user,
                    "alert_type": "Impossible Travel",
                    "from_location":
                        current_event["location"],

                    "to_location":
                        next_event["location"],

                    "time_difference_minutes":
                        round(time_difference, 2),

                    "risk_score": risk_score,

                    "severity":
                        classify_severity(risk_score)
                }

                alerts.append(alert)

    return alerts


if __name__ == "__main__":

    logs = load_logs()

    alerts = detect_impossible_travel(logs)

    print("\n=== Impossible Travel Alerts ===\n")

    for alert in alerts:
        print(alert)