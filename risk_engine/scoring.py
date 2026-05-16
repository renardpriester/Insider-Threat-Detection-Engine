RISK_SCORES = {
    "failed_login": 10,
    "failed_mfa": 25,
    "dormant_account_login": 40,
    "impossible_travel": 50,
    "privilege_escalation": 70,
    "mass_download": 80
}

def calculate_risk(event_type):

    return RISK_SCORES.get(event_type, 0)

def classify_severity(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"
    risk_rules = {
    "impossible_travel": 50,
    "after_hours_access": 40
}