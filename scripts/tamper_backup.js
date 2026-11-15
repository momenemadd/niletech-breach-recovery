'use strict';
// Recovery-technique demo: corrupt ONE byte of the local copy of a backup, then restore.
// The SHA-256 check rejects the damaged local copy and the restore falls back to the read-only
// offsite copy (3-2-1 rule). Usage: node scripts/tamper_backup.js [file]   (default: newest backup)
const fs = require('fs');
const path = require('path');
const backup = require('../lib/backup');

const file = process.argv[2] || (backup.listBackups()[0] || {}).file;
if (!file) { console.error('No backups found'); process.exit(1); }
const p = path.join(backup.LOCAL_DIR, file);
const buf = fs.readFileSync(p);
const pos = Math.floor(buf.length / 2);
buf[pos] ^= 0xff;                                   // flip one byte (simulates ransomware/disk damage)
fs.writeFileSync(p, buf);
console.log(`Flipped byte ${pos} of local copy ${file}`);
console.log('Verify now:', backup.verifyBackup(file));
