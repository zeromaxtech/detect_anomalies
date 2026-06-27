"""
generate_sample_log.py
Creates a realistic sample authentication log (CSV) with normal traffic
plus a few deliberately injected anomalies, so we have something
real to detect in the next script.
"""
import csv
import random
from datetime import datetime, timedelta

random.seed(42)

users = ["nikhel", "admin", "svc_backup", "j.mueller", "a.schmidt", "guest"]
normal_ips = ["192.168.1.10", "192.168.1.14", "10.0.0.5", "10.0.0.8", "192.168.1.22"]
suspicious_ip = "203.0.113.77"   # an external-looking IP we'll use for the attack pattern

rows = []
start = datetime(2026, 6, 20, 8, 0, 0)

# 1. Normal daytime logins across the week (success, occasional one failed-then-success)
current = start
for _ in range(150):
    user = random.choice(users)
    ip = random.choice(normal_ips)
    hour_offset = random.randint(0, 11)  # business hours 8am-7pm
    minute_offset = random.randint(0, 59)
    ts = current.replace(hour=8) + timedelta(hours=hour_offset, minutes=minute_offset)
    status = random.choices(["SUCCESS", "FAILED"], weights=[95, 5])[0]
    rows.append([ts.isoformat(), user, ip, status])
    current += timedelta(hours=random.randint(0, 6))

# 2. ANOMALY A: brute-force pattern - same IP, many failed logins in a short window
attack_start = datetime(2026, 6, 23, 3, 14, 0)  # 3am - off hours
for i in range(25):
    ts = attack_start + timedelta(seconds=i * 8)
    rows.append([ts.isoformat(), "admin", suspicious_ip, "FAILED"])
# then one success right after - classic "they got in" pattern
rows.append([(attack_start + timedelta(seconds=25 * 8 + 5)).isoformat(), "admin", suspicious_ip, "SUCCESS"])

# 3. ANOMALY B: odd-hour login for a normally 9-5 user, from a normal IP (insider-risk style)
odd_hour_ts = datetime(2026, 6, 24, 2, 47, 0)
rows.append([odd_hour_ts.isoformat(), "j.mueller", "192.168.1.14", "SUCCESS"])

# 4. ANOMALY C: one IP making a high volume of requests across many different accounts (scanning behaviour)
scan_start = datetime(2026, 6, 25, 14, 0, 0)
for i, user in enumerate(["admin", "svc_backup", "guest", "j.mueller", "a.schmidt", "nikhel", "root", "test"]):
    ts = scan_start + timedelta(seconds=i * 3)
    rows.append([ts.isoformat(), user, suspicious_ip, "FAILED"])

# Sort everything by timestamp like a real log file would be
rows.sort(key=lambda r: r[0])

with open("auth_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "user", "ip_address", "status"])
    writer.writerows(rows)

print(f"Generated auth_log.csv with {len(rows)} log entries.")
