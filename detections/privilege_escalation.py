import pandas as pd

def detect_privilege_escalation(logs_df):

    alerts = []

    suspicious = logs_df[
        logs_df["action"] == "admin_access"
    ]

    for _, row in suspicious.iterrows():

        alerts.append({
            "user": row["user"],
            "alert_type": "PrivilegeEscalation",
            "risk_score": 85,
            "severity": "HIGH",
            "details": "Unauthorized privileged access attempt detected"
        })

    return pd.DataFrame(alerts)