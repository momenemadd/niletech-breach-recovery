# Build log - Group 32 (5% of grade: setup notes, key commands/config, who did what)

Add a dated line each time someone works on the project. Keep it short and factual.

| Date | Member | What was done | Key commands / config |
| --- | --- | --- | --- |
| 2026-11-15 | Group | Chose base repo singh-70-9-shreyansh/waf-bruteforce-detection (MIT); gap analysis vs Option 3 brief | - |
| 2026-11-15 | Group | Migrated MySQL -> SQLite (security.db + company.db); bcrypt users with 3 roles | `npm run setup` |
| 2026-11-15 | Group | Fixed: plaintext password logging, dashboard XSS, hard-coded creds, fallback session secret | - |
| 2026-11-15 | Group | Rules R1/R2/R3 + protection mode ON/OFF; JSON-lines log `logs/auth.log` | `config.js` R1 5/5 min, R3 10 min |
| 2026-11-15 | Group | Encrypted backup (AES-256-GCM), SHA-256 manifest, offsite copy, known-good restore | `npm run backup`, `npm run restore` |
| 2026-11-15 | Group | Traffic scripts + Python detector + 7-day synthetic dataset; threshold sweep -> 5 | `npm run attack`, `python detector/detect.py ... --sweep` |
|  |  |  |  |

## Test results to record before the demo
| Test | Expected | Result / date |
| --- | --- | --- |
| Normal traffic only | 0 R1/R3 alerts | |
| Attack, protection OFF | R1 -> R3 -> R4, records 20 -> 12 | Passed 2026-11-15 (password found on try 8, 20 -> 12) |
| Restore known-good | 20 records, checksum match, time < 15 min | Passed 2026-11-15 (12 -> 20, checksum match, about 12 ms) |
| Tampered local backup | falls back to offsite copy | |
| Attack, protection ON | IP blocked, R3 locks account, no data touched | Passed 2026-11-15 (blocked 10/20/40 s, then account locked) |
| Synthetic dataset | precision 1.0, recall 0.667 (slow attacker missed) | Passed 2026-11-15 |
