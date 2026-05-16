import pandas as pd

def detect_data_exfiltration(logs_df):

    alerts = []

    suspicious = logs_df[
        logs_df["bytes_transferred"] > 500000
    ]

    for _, row in suspicious.iterrows():

        alerts.append({
            "user": row["user"],
            "alert_type": "DataExfiltration",
            "risk_score": 95,
            "severity": "CRITICAL",
            "details": f"Large outbound transfer detected ({row['bytes_transferred']} bytes)"
        })

    return pd.DataFrame(alerts)