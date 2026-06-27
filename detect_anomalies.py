"""
detect_anomalies.py
A simple security log anomaly detector.

Reads an authentication log (timestamp, user, ip_address, status) and flags
three common patterns analysts look for:

1. Brute-force attempts  -> many FAILED logins from the same IP in a short window
2. Off-hours logins       -> SUCCESS logins outside normal business hours (08:00-19:00)
3. Account scanning       -> one IP attempting logins against many different usernames

This is intentionally rule-based and readable rather than ML-based, because in a
real security operations context, simple, explainable rules are usually the
first line of defense before anything more complex is introduced.
"""
import pandas as pd

BUSINESS_HOUR_START = 7
BUSINESS_HOUR_END = 21

FAILED_LOGIN_THRESHOLD = 5       # flag if an IP has >= this many failures...
FAILED_LOGIN_WINDOW_MIN = 10     # ...within this many minutes
SCAN_DISTINCT_USER_THRESHOLD = 4  # flag if an IP tries this many different usernames...
SCAN_WINDOW_MIN = 5               # ...within this many minutes


def load_log(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def find_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    """Flag IPs with a burst of failed logins in a short rolling window."""
    failed = df[df["status"] == "FAILED"].copy()
    flags = []

    for ip, group in failed.groupby("ip_address"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()

        # sliding window check: for each failed attempt, count how many other
        # failed attempts from the same IP fall within FAILED_LOGIN_WINDOW_MIN
        for i, t in enumerate(timestamps):
            window_end = t + pd.Timedelta(minutes=FAILED_LOGIN_WINDOW_MIN)
            count_in_window = sum(1 for t2 in timestamps if t <= t2 <= window_end)
            if count_in_window >= FAILED_LOGIN_THRESHOLD:
                flags.append({
                    "ip_address": ip,
                    "window_start": t,
                    "failed_attempts_in_window": count_in_window,
                    "reason": "Brute-force pattern: repeated failed logins in a short time window"
                })
                break  # one flag per IP is enough to report

    return pd.DataFrame(flags)


def find_off_hours_logins(df: pd.DataFrame) -> pd.DataFrame:
    """Flag successful logins outside normal business hours."""
    success = df[df["status"] == "SUCCESS"].copy()
    success["hour"] = success["timestamp"].dt.hour
    off_hours = success[
        (success["hour"] < BUSINESS_HOUR_START) | (success["hour"] >= BUSINESS_HOUR_END)
    ].copy()
    off_hours["reason"] = "Successful login outside normal business hours (07:00-21:00)"
    return off_hours[["timestamp", "user", "ip_address", "reason"]]


def find_account_scanning(df: pd.DataFrame) -> pd.DataFrame:
    """Flag IPs that attempt logins against many distinct usernames quickly."""
    flags = []

    for ip, group in df.groupby("ip_address"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()
        users = group["user"].tolist()

        for i, t in enumerate(timestamps):
            window_end = t + pd.Timedelta(minutes=SCAN_WINDOW_MIN)
            users_in_window = {
                u for t2, u in zip(timestamps, users) if t <= t2 <= window_end
            }
            if len(users_in_window) >= SCAN_DISTINCT_USER_THRESHOLD:
                flags.append({
                    "ip_address": ip,
                    "window_start": t,
                    "distinct_users_targeted": len(users_in_window),
                    "users": ", ".join(sorted(users_in_window)),
                    "reason": "Account scanning pattern: many distinct usernames targeted quickly"
                })
                break

    return pd.DataFrame(flags)


def main():
    df = load_log("auth_log.csv")
    print(f"Loaded {len(df)} log entries from auth_log.csv\n")

    print("=" * 60)
    print("1. BRUTE-FORCE LOGIN DETECTION")
    print("=" * 60)
    brute_force = find_brute_force(df)
    if brute_force.empty:
        print("No brute-force patterns detected.\n")
    else:
        print(brute_force.to_string(index=False), "\n")

    print("=" * 60)
    print("2. OFF-HOURS LOGIN DETECTION")
    print("=" * 60)
    off_hours = find_off_hours_logins(df)
    if off_hours.empty:
        print("No off-hours logins detected.\n")
    else:
        print(off_hours.to_string(index=False), "\n")

    print("=" * 60)
    print("3. ACCOUNT SCANNING DETECTION")
    print("=" * 60)
    scanning = find_account_scanning(df)
    if scanning.empty:
        print("No account scanning patterns detected.\n")
    else:
        print(scanning.to_string(index=False), "\n")

    # Save a combined summary report
    with open("anomaly_report.txt", "w") as f:
        f.write("SECURITY LOG ANOMALY REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write("BRUTE-FORCE PATTERNS:\n")
        f.write(brute_force.to_string(index=False) if not brute_force.empty else "None detected")
        f.write("\n\nOFF-HOURS LOGINS:\n")
        f.write(off_hours.to_string(index=False) if not off_hours.empty else "None detected")
        f.write("\n\nACCOUNT SCANNING:\n")
        f.write(scanning.to_string(index=False) if not scanning.empty else "None detected")
        f.write("\n")

    print(f"Full report saved to anomaly_report.txt")


if __name__ == "__main__":
    main()
