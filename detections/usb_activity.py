import pandas as pd

def detect_usb_activity(logs_df):

    alerts = []

    suspicious = logs_df[
        logs_df["device"] == "USB"
    ]

    for _, row in suspicious.iterrows():

        alerts.append({
            "user": row["user"],
            "alert_type": "USBDataTransfer",
            "risk_score": 75,
            "severity": "HIGH",
            "details": "Sensitive files copied to USB device"
        })

    return pd.DataFrame(alerts)