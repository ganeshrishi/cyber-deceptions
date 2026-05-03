import pandas as pd
from sklearn.ensemble import IsolationForest

print("Starting ML analysis...")

# Read logs
data = []

with open("logs.txt", "r") as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) > 0:
            ip = parts[0]
            data.append(ip)

# Convert to DataFrame
df = pd.DataFrame(data, columns=["ip"])

# Count number of attempts per IP
counts = df.value_counts().reset_index(name="attempts")

print("\nLogin Attempts per IP:\n")
print(counts)

# Apply ML Model
model = IsolationForest(contamination=0.2)
model.fit(counts[["attempts"]])

counts["anomaly"] = model.predict(counts[["attempts"]])

print("\nDetection Result:\n")
print(counts)

# Alert system
print("\nAlerts:\n")
alerts = []
for i in range(len(counts)):
    if counts["anomaly"][i] == -1:
        alert = f"⚠️ Suspicious IP Detected: {counts['ip'][i]}"
        print(alert)
        alerts.append(alert)

# Save results to file
with open("analysis_output.txt", "w") as f:
    f.write("=== Cyber Deception ML Analysis Report ===\n\n")
    f.write("Login Attempts per IP:\n")
    f.write(str(counts) + "\n\n")
    f.write("Alerts:\n")
    for alert in alerts:
        f.write(alert + "\n")
    if not alerts:
        f.write("No suspicious activity detected.\n")

print("\n✓ Results saved to analysis_output.txt")