#!/usr/bin/env python3
"""
Synthetic log generator - 7 days of NileTech authentication activity in the same JSON-lines format
the web app writes (logs/auth.log), plus a ground-truth file for measuring the detector.

What is inside (deterministic, seed 2026):
  * Normal traffic : 20 employees, office hours Sun-Thu (Egyptian work week), ~1-3 logins/day,
                     ~20 % with 1-2 typos, a few remote workers on public IPs
  * Near misses    : two benign users who fail 3-4 times (forgot password) - must NOT alert at threshold 5
  * Shared NAT     : the office proxy 10.0.0.1 where several users mistype - tests false positives
  * Attack 1       : brute force on hr.manager from 203.0.113.66 at night, success, records read + deleted
  * Attack 2       : password spray from 198.51.100.23 (one password, many usernames), no success
  * Attack 3       : slow brute force from 192.0.2.77 (1 try / 3 min) - stays under the 5-in-5-min rule
                     on purpose, to show what the threshold misses (discussed in the report)

Usage: python detector/generate_synthetic_logs.py [--out logs/synthetic_auth.log] [--days 7]
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

EMPLOYEES = [f"emp{i:02d}" for i in range(1, 19)] + ["hr.manager", "secadmin"]
REMOTE = {"emp05": "41.33.120.7", "emp11": "156.204.18.90", "emp16": "197.38.44.12"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="logs/synthetic_auth.log")
    ap.add_argument("--truth", default="logs/synthetic_truth.json")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    events = []

    def ev(ts, event, ip, user, result, detail=None):
        events.append({"ts": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
                       "event": event, "ip": ip, "username": user, "result": result, "detail": detail})

    start = datetime(2026, 11, 1, tzinfo=timezone.utc)            # Sunday
    office_ip = {u: f"10.0.0.{20 + i}" for i, u in enumerate(EMPLOYEES)}
    office_ip.update(REMOTE)

    # ---- normal traffic ----
    for d in range(a.days):
        day = start + timedelta(days=d)
        if day.weekday() in (4, 5):                                # Fri, Sat weekend in Egypt
            continue
        for u in EMPLOYEES:
            for _ in range(rnd.randint(1, 3)):
                t = day + timedelta(hours=rnd.uniform(6, 15))      # 08:00-17:00 Cairo = 06-15 UTC
                ip = "10.0.0.1" if rnd.random() < 0.3 and u not in REMOTE else office_ip[u]  # some via proxy
                if rnd.random() < 0.2:
                    for _ in range(rnd.choice([1, 1, 2])):
                        ev(t, "LOGIN_FAIL", ip, u, "failed")
                        t += timedelta(seconds=rnd.uniform(4, 20))
                ev(t, "LOGIN_SUCCESS", ip, u, "ok")
                if u == "hr.manager":
                    t += timedelta(seconds=rnd.uniform(10, 60))
                    ev(t, "DATA_ACCESS", ip, u, "ok", "read 20 employee records")
                ev(t + timedelta(minutes=rnd.uniform(5, 240)), "LOGOUT", ip, u, "ok")

    # ---- near misses (benign, 3-4 fails) ----
    for u, n, d in (("emp07", 4, 1), ("emp13", 3, 3)):
        t = start + timedelta(days=d, hours=7, minutes=12)
        for _ in range(n):
            ev(t, "LOGIN_FAIL", office_ip[u], u, "failed"); t += timedelta(seconds=25)
        ev(t + timedelta(seconds=40), "LOGIN_SUCCESS", office_ip[u], u, "ok")

    # ---- attack 1: brute force -> success -> exfiltration + deletion (day 4, 01:13 UTC) ----
    t = start + timedelta(days=4, hours=1, minutes=13)
    atk = "203.0.113.66"
    for _ in range(7):
        ev(t, "LOGIN_FAIL", atk, "hr.manager", "failed"); t += timedelta(seconds=rnd.uniform(0.3, 1.2))
    ev(t, "LOGIN_SUCCESS", atk, "hr.manager", "ok"); t += timedelta(seconds=2)
    ev(t, "DATA_ACCESS", atk, "hr.manager", "ok", "read 20 employee records"); t += timedelta(seconds=1)
    for i in range(1, 9):
        ev(t, "DATA_DELETE", atk, "hr.manager", "ok", f"employee id {i}"); t += timedelta(seconds=0.1)

    # ---- attack 2: password spray (day 2, 22:40 UTC) ----
    t = start + timedelta(days=2, hours=22, minutes=40)
    for u in rnd.sample(EMPLOYEES[:18], 8):
        ev(t, "LOGIN_FAIL", "198.51.100.23", u, "failed"); t += timedelta(seconds=rnd.uniform(5, 15))

    # ---- attack 3: low-and-slow brute force (day 5) - evades a 5-in-5-min rule ----
    t = start + timedelta(days=5, hours=3)
    for _ in range(15):
        ev(t, "LOGIN_FAIL", "192.0.2.77", "secadmin", "failed"); t += timedelta(minutes=3)

    events.sort(key=lambda e: e["ts"])
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    truth = {"malicious_ips": ["203.0.113.66", "198.51.100.23", "192.0.2.77"],
             "breached": [{"ip": "203.0.113.66", "username": "hr.manager"}],
             "notes": {"192.0.2.77": "low-and-slow, expected to be missed by R1 at 5/5min",
                       "198.51.100.23": "spray: caught by R1 (8 fails) and R2"}}
    with open(a.truth, "w", encoding="utf-8") as f:
        json.dump(truth, f, indent=2)
    print(f"Wrote {len(events)} events to {a.out} and ground truth to {a.truth}")


if __name__ == "__main__":
    main()
