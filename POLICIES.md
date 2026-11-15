# Data Breach Detection & Recovery: Security Policies

NileTech Ltd (simulated) · Data Privacy project, Group 32 · Nov 15, 2026
Live version: https://claude.ai/artifact/MsqTDbVrpatjNeSo3n3uKi

## Purpose & scope

Six short policies govern the simulated company in our build, and every rule maps to a setting, script or screen in the code. The traceability table at the end lists where each one lives.

- **Organisation:** a fictional small company ("NileTech Ltd", ~20 employees) with employee accounts and one sensitive data store (employee records).
- **System in scope:** the web app (login page, admin/SOC dashboard, sensitive-records page), its database, its log files, and the backup store.
- **Threat in scope:** one scenario only. A brute-force login from one IP is followed by a successful login and access to sensitive data.
- **Owners:** Group 32 (Zeyad, Momen, Youssef, Mohamed). Review before the Week 12 demo and after any test incident.

## Policy 1: Access control & authentication

Only authenticated users may reach the app, and each sees only what their role needs (least privilege).

| Role | Can access | Cannot access |
| --- | --- | --- |
| Employee | Own profile, general pages | Sensitive records, dashboard |
| HR / Data owner | Sensitive records (read, delete) | Dashboard, backups |
| Security admin (SOC) | Dashboard, alerts, unblock, backup & restore | Edit sensitive records |

- **Passwords:** minimum 10 characters with upper case, lower case, a digit and a symbol, and no common words. They are stored only as **bcrypt** hashes, never as plain text.
- **No hard-coded credentials** in source code. Secrets live in a `.env` file excluded from Git.
- **Lockout:** 5 failed attempts from one IP in 5 minutes blocks that IP for 60 s, doubling on each repeat (60 s → 120 s → 240 s). The live demo shortens the base to 10 s (`BLOCK_BASE_MS` in `.env`).
- **Sessions:** HttpOnly cookie that expires after 30 minutes idle. Logout destroys the session.
- **Separate admin accounts:** admin accounts are kept separate from everyday accounts.

## Policy 2: Logging & monitoring

Every authentication and sensitive-data event is logged in a fixed format. No log ever contains a password or the sensitive data itself.

- **Logged fields:** timestamp (UTC, ISO-8601), source IP, username, event type (`LOGIN_FAIL`, `LOGIN_SUCCESS`, `IP_BLOCKED`, `DATA_ACCESS`, `BACKUP`, `RESTORE`) and result.
- **Never logged:** passwords (even failed ones), session IDs, record contents.
- **Format:** one JSON object per line in `logs/auth.log`, so the Python detector and the dashboard read the same data.
- **Integrity:** logs are append-only for the app. Only the security admin can clear them, and clearing is itself logged.
- **Retention:** 90 days, then deleted. The dashboard refreshes live via Socket.IO.
- **Time sync:** all components use server time, so the order of events in the detection window is reliable.

## Policy 3: Detection & alerting thresholds

Three rules run on every login and on the log file. The third (failures then success) is the breach signal and triggers the full response.

| Rule | Condition | Severity | Automatic action |
| --- | --- | --- | --- |
| R1 Brute force | ≥ 5 `LOGIN_FAIL` from one IP within 5 min | High | Block IP (60 s, doubling), dashboard alert |
| R2 Password spray | ≥ 3 different usernames failing from one IP within 5 min | Medium | Dashboard alert |
| R3 Probable breach | R1 fired for an IP, then `LOGIN_SUCCESS` from that IP within 10 min | Critical | Kill session, lock account, force password reset, alert + start Policy 6 |

- **Why 5 failures in 5 minutes:** normal users in our synthetic traffic fail at most 2–3 times. The threshold sweep on 7 days of synthetic logs shows 5 is the lowest threshold with 0 false positives.
- **One config file:** thresholds live in `config.js`, so they can be tuned and justified in the demo.
- **Alert records:** every alert records the rule ID, IP, username and time, and stays open until an admin acknowledges it.

## Policy 4: Data classification & handling

All data in the system carries one of three labels, and the label decides who may see it and how it is stored.

| Label | Examples in our build | Handling |
| --- | --- | --- |
| Confidential | Employee salaries, national IDs, contact details | HR role only; encrypted in backups; every access logged as `DATA_ACCESS` |
| Internal | Login logs, alerts, blocked-IP list | Security admin only; 90-day retention |
| Public | Login page, company name | No restriction |

- **Data minimisation:** store only the fields the demo needs. All records are synthetic, with no real personal data.
- **Display masking:** national IDs are shown as `**********1234` on screen.

## Policy 5: Backup & recovery

The sensitive data store is backed up automatically, encrypted and verified by checksum. It can be restored in under 15 minutes (RTO), losing at most 1 hour of data (RPO).

- **Schedule:** an automated backup every hour, plus an on-demand backup from the dashboard before any risky change.
- **3-2-1 rule (simulated):** 3 copies (live DB, local backup folder, "offsite" folder) in 2 locations, with 1 copy kept read-only.
- **Encryption:** each backup file is encrypted with AES-256-GCM. The key is in `.env` and never stored next to the backup.
- **Integrity:** a SHA-256 hash is saved for each backup. Restore refuses a file whose hash does not match and falls back to the offsite copy.
- **Retention:** the last 24 local backups. Offsite keeps everything from the last 24 h, then the newest backup per day for 7 days.
- **Known-good point:** after a breach, restore from the newest backup taken *before* the first R1 alert, not simply the latest one.
- **Restore steps:**
  1. Isolate: block the attacker IP, lock the affected account, put the app in maintenance mode.
  2. Pick the last known-good backup (timestamp before the attack).
  3. Verify its SHA-256 hash, then decrypt it.
  4. Restore to the database, comparing the record count and hash with the backup manifest.
  5. Smoke test: log in as HR and open the records page.
  6. Re-open the app and log `RESTORE` with its duration, measured against the RTO.
- **Testing:** a restore is run at least once before the demo and the measured time is recorded.

## Policy 6: Incident response & breach notification

A Critical (R3) alert starts the response immediately. If personal data was exposed, the regulator is told within 72 hours, as Egypt's PDPL (Law 151/2020) requires.

| Role (simulated) | Group member | Build area they own | Responsibility in an incident |
| --- | --- | --- | --- |
| Incident lead | Member A (name TBD) | Threat & risk analysis, these policies | Declares the incident, decides containment and restore, signs off recovery |
| Detection analyst | Member B (name TBD) | Traffic scripts, rules R1–R3, `detect.py` | Confirms the R3 alert in dashboard and logs, scopes affected accounts and records |
| Recovery engineer | Member C (name TBD) | `lib/backup.js`, backup and restore scripts | Picks the known-good backup, runs verified restore, records actual RTO |
| Communications / DPO | Member D (name TBD) | Dashboard, integration, testing, build log | Notifies management, staff and regulator; writes the incident report |

- **Phases:** Detect → Contain (block IP, lock account, kill session) → Eradicate (reset password, review other accounts) → Recover (Policy 5) → Lessons learned.
- **Communication:**
  - management within 1 hour;
  - affected staff after containment;
  - the Personal Data Protection Centre within 72 hours of awareness;
  - affected individuals within 3 working days after that.
- **Evidence:** export the log lines and alert record before clearing anything.
- **Post-incident:** a short report (timeline, root cause, data affected, actual vs target RTO) within 5 working days.

Sources: [Al Tamimi: PDPL Executive Regulations](https://www.mondaq.com/data-protection/1734370/from-policy-to-practice-egypt-issues-executive-regulations-of-the-personal-data-protection-law), [Clyde & Co: Egypt regulatory update](https://www.clydeco.com/fr/insights/2026/01/egypt-regulatory-update-on-data-privacy)

## Policy-to-code traceability

Each policy is backed by something you can show live in the build.

| Policy | Where it lives in the build | Status |
| --- | --- | --- |
| P1 Lockout + doubling block | `lib/detection.js` → `afterFailure()`, `config.js` | Done (5 / 5 min) |
| P1 bcrypt, roles, no hard-coded creds, password rules | `server.js` login, `lib/passwords.js`, `.env` | Done |
| P2 Structured log, no passwords | `lib/logger.js` → `logs/auth.log` | Done |
| P3 R1 brute force, R2 spray | `lib/detection.js` + `detector/detect.py` | Done |
| P3 R3 fails-then-success | `afterSuccess()` + `detect.py` (plus R4 data-impact rule) | Done |
| P4 Sensitive records page + masking | `public/records.html`, `/api/records` (HR only) | Done |
| P5 Encrypted, hashed backup + known-good restore | `lib/backup.js`, `scripts/backup.js`, `scripts/restore.js`, dashboard | Done |
| P6 Containment | Dashboard "Contain" button → `/api/contain` | Done |
| P6 One-page runbook | Runbook referencing the above | To write |
| Traffic simulation | `scripts/normal_traffic.js`, `scripts/bruteforce.js` | Done |
