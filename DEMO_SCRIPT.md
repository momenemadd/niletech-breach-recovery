# Demo script: Scene 1 (breach) + Scene 2 (recovery), from VS Code

## 0. Open the project (once per session)
1. Open **VS Code**, then **File → Open Folder…** and pick
   `D:\Users\Momen\Downloads\niletech-breach-recovery\niletech-breach-recovery`
   (the inner folder, the one that contains `package.json`).
2. Open the terminal with **Ctrl + `**.
3. Make **3 terminals** by clicking **+** twice. Rename them (right-click → Rename) to:
   **server**, **python**, **attack**.

> If PowerShell says "running scripts is disabled", run this once:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`, then answer `Y`.
> First time on a new laptop only: run `npm install` and then `npm run setup`.

---

## 1. Clean start (before every rehearsal / the real demo)
**server** terminal:
```
npm run reset-demo
npm start
```
Wait for: `NileTech app on http://localhost:3001 | protection mode: ON`, then leave this terminal alone.

**python** terminal:
```
python detector/detect.py logs/auth.log --follow
```
Wait for: `Watching logs/auth.log for new events...`

**Browser:** open **http://localhost:3001** and log in as `secadmin` / `Nt!S0c-Adm1n#77`.

---

## 2. Scene 1: the breach (protection OFF)
| # | Where | Do | What the audience sees |
| --- | --- | --- | --- |
| 1 | Dashboard | Click **Turn protection OFF** | Badge turns red: **PROTECTION OFF** |
| 2 | attack | `npm run traffic:normal` | Normal logins with a few typos, **no alerts** |
| 3 | attack | `npm run attack` | Tries passwords, then **PASSWORD FOUND "Summer@2026"**, **EXFILTRATED 20 records**, **deleted 8 records** |
| 4 | Dashboard | Point at the alerts | **High R1**, then **Critical R3** (with a beep): "attacker is logged in" |
| 5 | Dashboard | Point at the tile | **Employee records: 20 → 12** |
| 6 | python | Point at the terminal | Same alerts from the Python script: **R1 → R3 "ATTACKER IS IN" → R4** (read + deleting) |

**Say:** "The detection rule is 5 failed logins from one IP in 5 minutes, followed by a success within 10 minutes. It fired in both the web app and the independent Python log parser."

---

## 3. Scene 2: response and recovery
| # | Where | Do | What the audience sees |
| --- | --- | --- | --- |
| 1 | Dashboard | On the Critical R3 alert, click **Contain** | IP `203.0.113.66` in **Blocked IPs**, `hr.manager` in **Locked accounts**, attacker kicked out |
| 2 | Dashboard | Point at **Incident recovery** | Attack start time + the **known-good backup taken BEFORE it** |
| 3 *(optional)* | attack | `npm run restore:list`, then `npm run tamper -- <oldest backup name>` | Backups table shows **HASH MISMATCH** for the local copy |
| 4 | Dashboard | Click **Restore known-good backup** | Green steps: hash verified → decrypted → integrity ok → 12 → 20 → checksum equal → **RTO MET** (step 1 says "using offsite copy" if you did step 3) |
| 5 | Dashboard | Point at the tile | **Employee records: 20** again |
| 6 | Dashboard | Locked accounts: type `Summer@2027`, click **Reset & unlock** | **Rejected**: password policy blocks common words |
| 7 | Dashboard | Type `Gq#K8-Teal-Gate9`, click **Reset & unlock** | Accepted, account unlocked |
| 8 | Dashboard | Click **Acknowledge all** | Open alerts 0: incident closed |

**Say:** "We restore from the last backup taken before the first alert, because later backups may contain the attacker's changes. The backup is encrypted, its hash is checked, and if the local copy is damaged we fall back to the offsite copy."

---

## 4. If something goes wrong
| Problem | Fix |
| --- | --- |
| Website does not open | The **server** terminal must show "NileTech app on http://localhost:3001". If not, run `npm start` |
| "Invalid username or password" for secadmin | Stop the server (Ctrl+C), `npm run reset-demo`, `npm start` |
| `EADDRINUSE` | Another server is still running in another terminal: Ctrl+C there |
| Python shows nothing new | Ctrl+C in **python** and start it again |
| Attack says "blocked" / "locked" | Protection is ON: click **Turn protection OFF** (or reset) |
| Need to repeat the demo | Ctrl+C **server** and **python**, then go back to step 1 |
