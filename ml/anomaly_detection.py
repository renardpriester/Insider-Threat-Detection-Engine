import pandas as pd

from sklearn.ensemble import IsolationForest


def detect_anomalies(alerts):

    df = pd.DataFrame(alerts)

    if df.empty:
        return pd.DataFrame()

    # Aggregate user behavior
    user_features = (
        df.groupby("user")
        .agg({
            "risk_score": "sum"
        })
        .reset_index()
    )

    # Train Isolation Forest
    model = IsolationForest(
        contamination=0.25,
        random_state=42
    )

    user_features["anomaly_score"] = model.fit_predict(
        user_features[["risk_score"]]
    )

    # Convert:
    # -1 = anomaly
    #  1 = normal
    user_features["is_anomaly"] = (
        user_features["anomaly_score"] == -1
    )

    return user_features
def detect_high_risk_activity(logs):
    alerts = []

    suspicious_activities = [
        "Privilege Escalation",
        "USB Data Transfer",
        "Mass Download",
        "Sensitive File Access"
    ]

    suspicious_locations = [
        "Russia",
        "China",
        "North Korea",
        "Iran"
    ]

    for log in logs:

        if (
            log.get("activity") in suspicious_activities
            and log.get("location") in suspicious_locations
        ):

            alerts.append({
                "user": log["user"],
                "alert_type": "HighRiskActivity",
                "activity": log["activity"],
                "location": log["location"],
                "risk_score": 90,
                "severity": "HIGH",
                "timestamp": log["timestamp"]
            })

    return alerts