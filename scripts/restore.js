'use strict';
// Restore procedure from the command line (the dashboard button runs exactly the same code).
//   node scripts/restore.js --list              list backups and whether local/offsite copies are intact
//   node scripts/restore.js --plan              show which backup is the known-good point and why
//   node scripts/restore.js                     restore the known-good backup
//   node scripts/restore.js --file <name>       restore a specific backup
const { openCompany, openSecurity } = require('../lib/db');
const backup = require('../lib/backup');
const { logEvent } = require('../lib/logger');

const args = process.argv.slice(2);
const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };

if (args.includes('--list')) {
  for (const m of backup.listBackups()) {
    const v = backup.verifyBackup(m.file);
    const tag = s => (s === 'ok' ? C.g(s) : C.r(s));
    console.log(`${m.created_at}  ${m.file}  ${String(m.records).padStart(3)} records  local:${tag(v.local)}  offsite:${tag(v.offsite)}  (${m.reason})`);
  }
  process.exit(0);
}

const sec = openSecurity();
const first = sec.prepare("SELECT * FROM alerts WHERE rule IN ('R1','R3') AND acknowledged = 0 ORDER BY ts ASC LIMIT 1").get();
let file = args.includes('--file') ? args[args.indexOf('--file') + 1] : null;
if (!file) {
  const chosen = first ? backup.chooseKnownGood(first.ts) : backup.listBackups()[0];
  console.log(C.b('Known-good point'));
  console.log(`  First attack alert : ${first ? new Date(first.ts).toISOString() + ' (' + first.rule + ')' : 'none'}`);
  console.log(`  Chosen backup      : ${chosen ? chosen.file + ' taken ' + chosen.created_at : C.r('none before the attack!')}`);
  if (first) for (const m of backup.listBackups().filter(m => m.created_ms >= first.ts)) console.log(C.y(`  Skipped (after attack, may hold attacker changes): ${m.file}`));
  if (!chosen) process.exit(1);
  file = chosen.file;
  if (args.includes('--plan')) process.exit(0);
}

console.log(C.b(`\nRestoring ${file}`));
try {
  const report = backup.restoreBackup(openCompany(), file, { reason: 'cli' });
  report.steps.forEach((s, i) => console.log(`  ${i + 1}. [${String(s.t_ms).padStart(5)} ms] ${s.ok ? C.g('OK  ') : C.y('WARN')} ${s.msg}`));
  logEvent('RESTORE', { result: report.within_rto ? 'ok' : 'rto_missed', detail: `cli: ${file} -> ${report.records} records in ${report.duration_ms} ms` });
  console.log(C.g(`\nRecovered ${report.records} records in ${(report.duration_ms / 1000).toFixed(2)} s.`));
} catch (e) {
  (e.steps || []).forEach((s, i) => console.log(`  ${i + 1}. ${s.ok ? 'OK  ' : 'WARN'} ${s.msg}`));
  console.error(C.r(`RESTORE FAILED: ${e.message}`));
  logEvent('RESTORE', { result: 'failed', detail: e.message });
  process.exit(1);
}
