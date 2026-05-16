"""
Simplified Linux Log Anomaly Detection Implementation

This script demonstrates the Linux-based part of the project:
1. Reading authentication logs
2. Parsing logs into event IDs
3. Generating event sequences
4. Applying frequency-based anomaly detection
5. Applying rule-based cybersecurity detection
6. Combining both using a hybrid approach

Note:
The complete project also included larger datasets, HDFS/BGL/Windows experiments,
Transformer-based models, and domain-adaptive learning using GRL.
"""

from collections import defaultdict
from sklearn.metrics import accuracy_score, precision_score, recall_score


def read_logs(file_path):
    """Read raw log lines from a file."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        logs = file.readlines()
    return logs


def parse_event(line):
    """Convert a raw Linux log line into an event ID."""
    line = line.lower()

    if "failed password" in line:
        return "E1"
    elif "accepted password" in line:
        return "E2"
    elif "sudo" in line:
        return "E3"
    elif "invalid user" in line:
        return "E4"
    elif "session closed" in line:
        return "E5"
    elif "connection closed" in line:
        return "E6"
    elif "pam" in line:
        return "E7"
    else:
        return "E0"


def create_sequences(events, window=3):
    """Generate sliding-window event sequences."""
    sequences = []

    for i in range(len(events) - window):
        sequences.append(events[i:i + window])

    return sequences


def build_frequency_model(sequences):
    """Build a frequency-based sequence probability model."""
    model = defaultdict(int)

    for seq in sequences:
        model[tuple(seq)] += 1

    total = sum(model.values())

    for key in model:
        model[key] = model[key] / total

    return model


def detect_anomaly(seq, model, threshold=0.05):
    """Detect anomaly based on low sequence probability."""
    probability = model.get(tuple(seq), 0)
    return probability < threshold


def rule_engine(events):
    """Detect known cybersecurity attack patterns using rules."""
    alerts = []

    consecutive_failed_logins = 0

    for event in events:
        if event == "E1":
            consecutive_failed_logins += 1

            if consecutive_failed_logins >= 5:
                alerts.append("Brute Force Attack Detected")
                consecutive_failed_logins = 0
        else:
            consecutive_failed_logins = 0

    if events.count("E4") > 5:
        alerts.append("User Enumeration Attack Detected")

    if events.count("E3") > 5:
        alerts.append("Excessive Sudo Usage / Possible Privilege Escalation Detected")

    return alerts


def main():
    file_path = "sample-data/sample-auth.log"

    logs = read_logs(file_path)
    print("Total logs:", len(logs))

    events = [parse_event(line) for line in logs]

    print("\nFirst 20 events:")
    print(events[:20])

    sequences = create_sequences(events, window=3)

    print("\nFirst 5 sequences:")
    print(sequences[:5])

    model = build_frequency_model(sequences)

    print("\nML Detected Anomalies:")
    for seq in sequences:
        if detect_anomaly(seq, model):
            print("Anomaly:", seq, "| Reason: Low probability sequence")

    alerts = rule_engine(events)

    print("\nRULE-BASED ALERTS:")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No rule-based alerts detected.")

    y_true = []
    for seq in sequences:
        if seq.count("E1") >= 2:
            y_true.append(1)
        else:
            y_true.append(0)

    y_pred_ml = []
    for seq in sequences:
        if detect_anomaly(seq, model):
            y_pred_ml.append(1)
        else:
            y_pred_ml.append(0)

    y_pred_rule = []
    for seq in sequences:
        if seq.count("E1") >= 3:
            y_pred_rule.append(1)
        else:
            y_pred_rule.append(0)

    y_pred_hybrid = []
    for i in range(len(sequences)):
        if y_pred_ml[i] == 1 or y_pred_rule[i] == 1:
            y_pred_hybrid.append(1)
        else:
            y_pred_hybrid.append(0)

    print("\n--- EVALUATION METRICS ---")

    print("\nML Model:")
    print("Accuracy:", accuracy_score(y_true, y_pred_ml))
    print("Precision:", precision_score(y_true, y_pred_ml, zero_division=0))
    print("Recall:", recall_score(y_true, y_pred_ml, zero_division=0))

    print("\nRule-Based Model:")
    print("Accuracy:", accuracy_score(y_true, y_pred_rule))
    print("Precision:", precision_score(y_true, y_pred_rule, zero_division=0))
    print("Recall:", recall_score(y_true, y_pred_rule, zero_division=0))

    print("\nHybrid Model:")
    print("Accuracy:", accuracy_score(y_true, y_pred_hybrid))
    print("Precision:", precision_score(y_true, y_pred_hybrid, zero_division=0))
    print("Recall:", recall_score(y_true, y_pred_hybrid, zero_division=0))


if __name__ == "__main__":
    main()
