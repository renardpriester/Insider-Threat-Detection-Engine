from detections.impossible_travel import (
    detect_impossible_travel
)

from detections.after_hours_access import (
    detect_after_hours_access,
    load_logs
)

from ml.anomaly_detection import (
    detect_anomalies
)

logs = load_logs()

travel_alerts = detect_impossible_travel(logs)

after_hours_alerts = detect_after_hours_access(logs)

alerts = (
    travel_alerts +
    after_hours_alerts
)

results = detect_anomalies(alerts)

print(results)