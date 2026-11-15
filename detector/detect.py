#!/usr/bin/env python3
"""
Breach detection script (Python log parser) - Policy 3 rules applied to the JSON-lines auth log.

  R1 Brute force     : >= THRESHOLD LOGIN_FAIL from one IP within WINDOW seconds          -> HIGH
  R2 Password spray  : >= SPRAY_USERS different usernames failing from one IP in WINDOW   -> MEDIUM
  R3 Probable breach : R1 fired for an IP, then LOGIN_SUCCESS from that IP within
                       SUCCESS_WINDOW seconds                                             -> CRITICAL
  R4 Data impact     : DATA_ACCESS / DATA_DELETE by the breached session (same IP + user)  -> CRITICAL

Usage
  python detector/detect.py logs/auth.log                    # analyse a log once
  python detector/detect.py logs/auth.log --follow           # live: keep watching the file for new lines
  python detector/detect.py logs/synthetic_auth.log --truth logs/synthetic_truth.json
  python detector/detect.py logs/synthetic_auth.log --truth logs/synthetic_truth.json --sweep

Standard library only (Python 3.8+). Writes a JSON report to reports/detection_report.json.
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

if os.name == "nt":
    os.system("")  # enable ANSI colours in the Windows terminal

RED, YEL, ORG, GRN, BLD, DIM, RST = "\033[31m", "\033[33m", "\033[38;5;208m", "\033[32m", "\033[1m", "\033[2m", "\033[0m"
SEV_COLOUR = {"CRITICAL": RED + BLD, "HIGH": ORG, "MEDIUM": YEL}


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


class Detector:
    def __init__(self, threshold=5, window=300, success_window=600, spray_users=3, quiet=False):
        self.t, self.w, self.sw, self.su, self.quiet = threshold, window, success_window, spray_users, quiet
        self.fails = defaultdict(deque)          # ip -> deque[(ts, username)]
        self.last_alert = {}                     # (rule, ip) -> ts
        self.r1_time = {}                        # ip -> ts of latest R1
        self.breached = {}                       # (ip, user) -> breach info
        self.alerts = []
        self.stats = defaultdict(lambda: {"fail": 0, "success": 0, "users": set()})
        self.events = 0

    def _alert(self, rule, sev, ts, ip, user, msg):
        a = {"time": iso(ts), "rule": rule, "severity": sev,
             "ip": ip, "username": user, "message": msg}
        self.alerts.append(a)
        if not self.quiet:
            c = SEV_COLOUR.get(sev, "")
            print(f"{c}[ALERT {sev:<8}] {rule}{RST} {a['time'][:19]}  {ip:<15} {user or '':<11} {msg}")
        return a

    def feed(self, ev):
        self.events += 1
        kind, ip, user = ev.get("event"), ev.get("ip"), ev.get("username")
        if not ip:
            return
        ts = parse_ts(ev["ts"])
        st = self.stats[ip]

        if kind == "LOGIN_FAIL":
            st["fail"] += 1
            st["users"].add(user)
            q = self.fails[ip]
            q.append((ts, user))
            while q and q[0][0] <= ts - self.w:
                q.popleft()
            if len(q) >= self.t and ts - self.last_alert.get(("R1", ip), -1e18) > self.w:
                self.last_alert[("R1", ip)] = ts
                self.r1_time[ip] = ts
                self._alert("R1", "HIGH", ts, ip, user,
                            f"{len(q)} failed logins within {self.w // 60} min (threshold {self.t})")
            users = {u for _, u in q}
            if len(users) >= self.su and ts - self.last_alert.get(("R2", ip), -1e18) > self.w:
                self.last_alert[("R2", ip)] = ts
                self._alert("R2", "MEDIUM", ts, ip, user, f"{len(users)} different usernames failing - password spray")

        elif kind == "LOGIN_SUCCESS":
            st["success"] += 1
            r1 = self.r1_time.get(ip)
            if r1 is not None and 0 <= ts - r1 <= self.sw:
                denied = ev.get("result") == "denied_r3"
                self.breached[(ip, user)] = {"ip": ip, "username": user, "login": ts, "denied": denied,
                                             "reads": 0, "records_read": 0, "deletes": 0}
                outcome = "login was refused by the app (protection ON)" if denied else "ATTACKER IS IN"
                self._alert("R3", "CRITICAL", ts, ip, user,
                            f"successful login {int(ts - r1)} s after brute-force alert - {outcome}")

        elif kind in ("DATA_ACCESS", "DATA_DELETE"):
            b = self.breached.get((ip, user))
            if b and not b["denied"]:
                if kind == "DATA_ACCESS":
                    b["reads"] += 1
                    try:
                        b["records_read"] += int(str(ev.get("detail", "")).split()[1])
                    except (IndexError, ValueError):
                        pass
                    self._alert("R4", "CRITICAL", ts, ip, user, f"breached session read data: {ev.get('detail')}")
                else:
                    b["deletes"] += 1
                    if b["deletes"] == 1:
                        self._alert("R4", "CRITICAL", ts, ip, user, "breached session started DELETING records")


def read_events(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def follow(path, det):
    print(f"{DIM}Watching {path} for new events (Ctrl+C to stop)...{RST}")
    while not os.path.exists(path):
        time.sleep(0.5)
    f = open(path, encoding="utf-8")
    f.seek(0, os.SEEK_END)
    try:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                if os.path.exists(path) and os.stat(path).st_size < f.tell():   # log was rotated / reset
                    f.close(); f = open(path, encoding="utf-8")
                continue
            try:
                det.feed(json.loads(line))
            except json.JSONDecodeError:
                pass
    except KeyboardInterrupt:
        print()


def evaluate(alerts, truth, rules=("R1", "R3")):
    """Precision/recall per IP: an IP is 'flagged' if any of `rules` fired for it."""
    bad = set(truth["malicious_ips"])
    flagged = {a["ip"] for a in alerts if a["rule"] in rules}
    tp, fp, fn = len(flagged & bad), len(flagged - bad), len(bad - flagged)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
            "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0,
            "false_positive_ips": sorted(flagged - bad), "missed_ips": sorted(bad - flagged)}


def summary(det, path):
    print(f"\n{BLD}Summary for {path}{RST}")
    print(f"  events processed : {det.events}")
    by_rule = defaultdict(int)
    for a in det.alerts:
        by_rule[a["rule"]] += 1
    print(f"  alerts           : {dict(by_rule) or 'none'}")
    top = sorted(det.stats.items(), key=lambda kv: -kv[1]["fail"])[:5]
    print(f"\n  {'IP':<16}{'fails':>6}{'success':>9}{'usernames':>11}")
    for ip, s in top:
        print(f"  {ip:<16}{s['fail']:>6}{s['success']:>9}{len(s['users']):>11}")
    for b in det.breached.values():
        print(f"\n{RED}{BLD}  INCIDENT: {b['username']} compromised from {b['ip']} at "
              f"{iso(b['login'])}{RST}")
        if b["denied"]:
            print(f"{GRN}    login refused + account locked by the app - no data accessed{RST}")
        else:
            print(f"    data reads: {b['reads']} ({b['records_read']} records exposed)   deletions: {b['deletes']}")
            print(f"    -> restore company data from the newest backup taken BEFORE the first R1 alert")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=300, help="seconds (default 300 = 5 min)")
    ap.add_argument("--success-window", type=int, default=600, help="seconds (default 600 = 10 min)")
    ap.add_argument("--spray-users", type=int, default=3)
    ap.add_argument("--follow", action="store_true", help="watch the log live")
    ap.add_argument("--truth", help="ground-truth JSON from generate_synthetic_logs.py")
    ap.add_argument("--sweep", action="store_true", help="try thresholds 2..10 and show false positives / misses")
    ap.add_argument("--report", default="reports/detection_report.json")
    a = ap.parse_args()

    if a.sweep:
        if not a.truth:
            sys.exit("--sweep needs --truth")
        truth = json.load(open(a.truth, encoding="utf-8"))
        events = list(read_events(a.logfile))
        print(f"{BLD}Threshold sweep (window {a.window}s) - R1 flagged IPs vs ground truth{RST}")
        print(f"  {'threshold':>9}{'TP':>5}{'FP':>5}{'FN':>5}{'precision':>11}{'recall':>8}")
        for t in range(2, 11):
            d = Detector(t, a.window, a.success_window, a.spray_users, quiet=True)
            for ev in events:
                d.feed(ev)
            e = evaluate(d.alerts, truth, rules=("R1",))
            mark = "  <- chosen" if t == a.threshold else ""
            print(f"  {t:>9}{e['tp']:>5}{e['fp']:>5}{e['fn']:>5}{e['precision']:>11}{e['recall']:>8}{mark}")
        return

    det = Detector(a.threshold, a.window, a.success_window, a.spray_users)
    print(f"{BLD}Breach detector{RST}  rules: R1 >= {a.threshold} fails/{a.window}s, R2 >= {a.spray_users} users, "
          f"R3 success <= {a.success_window}s after R1\n")
    if a.follow:
        follow(a.logfile, det)
    else:
        for ev in read_events(a.logfile):
            det.feed(ev)
    summary(det, a.logfile)

    report = {"log": a.logfile, "generated": iso(time.time()),
              "thresholds": vars(a), "events": det.events, "alerts": det.alerts,
              "incidents": [{**b, "login": iso(b["login"])} for b in det.breached.values()]}
    if a.truth:
        report["evaluation"] = evaluate(det.alerts, json.load(open(a.truth, encoding="utf-8")))
        e = report["evaluation"]
        print(f"\n  Evaluation vs ground truth: precision {e['precision']}  recall {e['recall']}  "
              f"(TP {e['tp']}, FP {e['fp']}, FN {e['fn']})")
    os.makedirs(os.path.dirname(a.report) or ".", exist_ok=True)
    with open(a.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=list)
    print(f"\n  Report written to {a.report}")


if __name__ == "__main__":
    main()
