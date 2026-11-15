'use strict';
// Automated backup script (Policy 5). Safe to run while the server is running.
// Schedule it with cron (Linux/macOS) or Task Scheduler (Windows) as an extra to the server's hourly job:
//   cron:  0 * * * *  cd /path/to/project && node scripts/backup.js
//   Windows: schtasks /create /sc hourly /tn NileTechBackup /tr "node C:\path\to\project\scripts\backup.js"
const { openCompany } = require('../lib/db');
const { createBackup } = require('../lib/backup');
const { logEvent } = require('../lib/logger');

const m = createBackup(openCompany(), process.argv[2] || 'cli');
logEvent('BACKUP', { result: 'ok', detail: `${m.reason}: ${m.file} (${m.records} records)` });
console.log(JSON.stringify(m, null, 2));
