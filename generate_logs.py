import json
import random
from datetime import datetime, timedelta, timezone
from faker import Faker

fake = Faker()

USERS = [
    "jdoe",
    "asmith",
    "mjones",
    "bwilliams",
    "admin1",
    "finance.user",
    "it.support"
]

LOCATIONS = [
    "New York",
    "Florida",
    "Texas",
    "California",
    "Germany",
    "Russia",
    "China",
    "London"
]

EVENT_TYPES = [
    "successful_login",
    "failed_login",
    "privilege_escalation",
    "mass_download",
    "failed_mfa",
    "dormant_account_login"
]

def generate_event():
    user = random.choice(USERS)
    event = random.choice(EVENT_TYPES)
    location = random.choice(LOCATIONS)

    timestamp = (
    datetime.now(timezone.utc) -
    timedelta(
        minutes=random.randint(1, 5000)
    )
).isoformat()

    risk_score = random.randint(1, 100)

    log = {
        "timestamp": timestamp,
        "user": user,
        "location": location,
        "event": event,
        "risk_score": risk_score,
        "ip_address": fake.ipv4(),
        "device": fake.user_agent()
    }

    return log

logs = []

for _ in range(100):
    logs.append(generate_event())
# Inject highly suspicious insider activity
for _ in range(15):

    logs.append({
        "user": "rogue.employee",
        "timestamp": fake.iso8601(),
        "location": random.choice([
            "Russia",
            "China",
            "North Korea",
            "Iran"
        ]),
        "activity": random.choice([
            "Sensitive File Access",
            "Privilege Escalation",
            "USB Data Transfer",
            "VPN Login",
            "Mass Download"
        ])
    })

with open("logs/mock_logs.json", "w") as f:
    json.dump(logs, f, indent=4)

print("Mock security logs generated successfully.")