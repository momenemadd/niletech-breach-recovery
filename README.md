# NileTech: Data Breach Detection & Recovery

Data Privacy project, Group 32, Option 3. A small company web app that **detects** a brute-force breach in its logs, **mitigates** it, and **recovers** the damaged data from encrypted, verified backups.

Based on [singh-70-9-shreyansh/waf-bruteforce-detection](https://github.com/singh-70-9-shreyansh/waf-bruteforce-detection) (MIT, see `CREDITS.md`). We moved it from MySQL to SQLite and rewrote and extended it. The table below lists what changed.

## Requirements
- Node.js **22.13 or newer**, current LTS recommended (`node -v`). It uses Node's built-in SQLite, so there's nothing to compile and no database server to install.
- Python 3.8 or newer, standard library only (`python --version`)

## Quick start
```bash
npm install
npm run setup          # creates .env (random secrets), databases, demo users, 20 records, first backup
npm start              # http://localhost:3001
```

| Account | Role | Password | Lands on |
| --- | --- | --- | --- |
| secadmin | Security admin | `Nt!S0c-Adm1n#77` | `/dashboard.html` |
| hr.manager | HR (data owner) | `Summer@2026` (weak legacy password, the root cause) | `/records.html` |
| a.hassan … k.samir | Employee | see `scripts/setup.js` | `/home.html` |

All data is synthetic.

## Project structure
```
server.js                 Express app: login, roles, records API, SOC API, backup/restore API, live updates
config.js                 every threshold from the Policies doc (R1/R2/R3, block time, RTO/RPO, retention)
lib/sqlite.js             wrapper over Node's built-in SQLite (node:sqlite)
lib/db.js                 security.db (users, attempts, alerts) + company.db (Confidential records)
lib/detection.js          rules R1 brute force, R2 spray, R3 fails-then-success + mitigation
lib/backup.js             AES-256-GCM backups, SHA-256 manifest, offsite copy, retention, verified restore
lib/logger.js             JSON-lines security log (never logs passwords)
lib/passwords.js          password policy (length, classes, banned common words)
public/                   login, employee home, HR records page, SOC dashboard (HTML/CSS/JS)
scripts/normal_traffic.js benign traffic generator
scripts/bruteforce.js     attack simulator (dictionary -> success -> exfiltrate -> delete)
scripts/backup.js         automated backup (cron / Task Scheduler)
scripts/restore.js        restore from the command line (same code as the dashboard button)
scripts/tamper_backup.js  corrupts a local backup to demo hash check + offsite fallback
detector/detect.py        Python log parser: R1-R4 alerts, incident summary, evaluation, threshold sweep
detector/generate_synthetic_logs.py  7-day synthetic dataset + ground truth
reports/log_profile.md    profile of the synthetic dataset
```

## Live demo script (about 8 minutes)
Open 3 terminals and a browser logged in as `secadmin`.

**Scene 1: the vulnerable system is breached** (requirement: show the alert firing)
1. `npm run reset-demo`, then `npm start` (terminal A).
2. On the dashboard click **Turn protection OFF**.
3. Terminal B: `python detector/detect.py logs/auth.log --follow` (the live detector).
4. Terminal C: `npm run traffic:normal`. No alerts appear, because normal typos stay under the threshold.
5. Terminal C: `npm run attack`. The password is found on try 8, then 20 records are exfiltrated and 8 deleted.
6. Both the dashboard and the Python detector fire **R1 → R3 (Critical, with a beep) → R4**. The record count drops from 20 to 12.

**Scene 2: incident response and recovery** (requirement: run the restore live and show data recovered)
1. On the R3 alert, click **Contain**. The attacker IP is blocked for 1 h and `hr.manager` is locked, which kills the attacker's session.
2. The Incident recovery panel shows the attack start time and the **known-good backup** taken before it. Backups taken after the attack are skipped.
3. Optional: run `npm run tamper -- <that backup file>` first, to show the restore rejecting the corrupted local copy and using the offsite copy.
4. Click **Restore known-good backup**. Six verified steps are shown and the record count returns to 20. The checksum matches, and the restore time is checked against the 15-minute RTO.
5. In Locked accounts, enter a strong new password and click **Reset & unlock**. `Summer@2027` is rejected by the policy.

**Scene 3: the hardening measure works**
1. `npm run reset-demo` and restart the server. Protection is ON.
2. Run `npm run attack`. The IP is blocked after 5 tries (10 s, then 20 s, then 40 s). When the right password finally arrives, R3 **refuses the login and locks the account**. No data is touched.

**Scene 4: detector accuracy on 7 days of data** (shows the threshold choice)
```bash
python detector/generate_synthetic_logs.py
python detector/detect.py logs/synthetic_auth.log --truth logs/synthetic_truth.json
python detector/detect.py logs/synthetic_auth.log --truth logs/synthetic_truth.json --sweep
```
Threshold 5 is the lowest with **0 false positives**. The low-and-slow attacker (192.0.2.77) is missed on purpose. It's a known limitation to discuss.

## Recovery techniques used (TA feedback)
| Technique | Where | What it proves |
| --- | --- | --- |
| Consistent hot snapshot (`VACUUM INTO`) | `lib/backup.js` | Backup can be taken while the app runs |
| AES-256-GCM encryption, key kept in `.env` | `lib/backup.js` | A stolen backup file leaks nothing; tampering is detected |
| SHA-256 manifest per backup | `*.db.enc.json` | Corrupted backups are rejected before use |
| 3-2-1 copies: live, local, read-only offsite | `backups/local`, `backups/offsite` | Restore survives loss or corruption of one copy |
| Hourly schedule + retention (24 local; offsite keeps 24 h, then newest per day for 7 days) | `server.js`, `scripts/backup.js` | RPO of 1 hour |
| Known-good point selection | `restorePlan()` | Never restores data the attacker already changed |
| Separate security DB | `lib/db.js` | Restore never erases evidence or unlocks the attacker |
| Transactional restore + integrity_check + post-restore checksum | `restoreBackup()` | All-or-nothing, verified exact recovery |
| Timed against RTO (15 min) | restore report | Recovery objective measured, not assumed |

## Changes from the original GitHub code
| Original | Now |
| --- | --- |
| MySQL | SQLite via Node's built-in `node:sqlite` (two DB files, no server, no native build) |
| Hard-coded `admin` / `Admin@123` | bcrypt-hashed users, 3 roles, least privilege |
| Logged every typed password to the console | Passwords never logged; structured JSON log instead |
| Dashboard used `innerHTML` with user data (XSS) | All text set with `textContent` |
| Fallback session secret `fallbacksecret` | Random secret in `.env`, server refuses to start without it |
| Only blocked IPs | R1 + R2 + R3 (fails-then-success) + manual containment |
| No data, no backup | Confidential records page, encrypted verified backup and restore |
| Anyone could clear logs/attempts | Evidence kept; only alerts can be acknowledged (logged) |

## Configuration
Every policy value lives in `config.js`, and any of them can be overridden in `.env`. The demo uses `BLOCK_BASE_MS=10000` (10 s) so the presentation doesn't wait minutes. The policy value is 60 s.
`SIMULATION_TRUST_XFF=true` lets the scripts pretend to be different IPs. It must be `false` on any real deployment.
