'use strict';
// Policy 5: backup & recovery for the Confidential company database.
//
// BACKUP  1. Consistent snapshot of company.db (SQLite "VACUUM INTO" - safe while the app runs)
//         2. Fingerprint: record count, SHA-256 of the plaintext file and of the table contents
//         3. Encrypt with AES-256-GCM (key from .env, never stored next to the backups)
//         4. SHA-256 of the encrypted file -> manifest (.json) beside it
//         5. Copy to the "offsite" folder and make that copy read-only (3-2-1 rule, simulated)
//         6. Retention: newest BACKUP_KEEP local copies; offsite keeps all of the last 24 h,
//           then the newest per day for 7 days
//
// RESTORE 1. Pick the last KNOWN-GOOD backup (taken before the first attack alert)
//         2. Verify SHA-256 of the encrypted file; if the local copy is damaged, fall back to offsite
//         3. Decrypt (GCM authentication fails if a single byte was tampered with)
//         4. Check plaintext SHA-256, SQLite integrity_check and record count against the manifest
//         5. Replace the live table contents inside one transaction (all-or-nothing)
//         6. Re-compute the table checksum on the live DB - must equal the manifest's
//         7. Measure the duration against the RTO target
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('./sqlite');
const cfg = require('../config');
const { abs, openCompany } = require('./db');

const LOCAL_DIR = abs(cfg.BACKUP_DIR);
const OFFSITE_DIR = abs(cfg.OFFSITE_DIR);
const MAGIC = Buffer.from('BDRB1');               // file format marker + version
const ALGO = 'aes-256-gcm';

function key() {
  if (!cfg.BACKUP_KEY_HEX) throw new Error('BACKUP_KEY missing in .env - run "npm run setup"');
  const k = Buffer.from(cfg.BACKUP_KEY_HEX, 'hex');
  if (k.length !== 32) throw new Error('BACKUP_KEY must be 64 hex characters (32 bytes)');
  return k;
}
const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');
const ensureDirs = () => [LOCAL_DIR, OFFSITE_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// Deterministic checksum of the employees table contents (order by id).
function tableChecksum(db, schema = 'main') {
  const rows = db.prepare(`SELECT * FROM ${schema}.employees ORDER BY id`).all();
  return { count: rows.length, sha256: sha256(Buffer.from(JSON.stringify(rows))) };
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv(ALGO, key(), iv);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), body]);
}
function decrypt(blob) {
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Not a backup file (bad header)');
  let o = MAGIC.length;
  const iv = blob.subarray(o, o += 12);
  const tag = blob.subarray(o, o += 16);
  const d = crypto.createDecipheriv(ALGO, key(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(blob.subarray(o)), d.final()]); // throws if tampered / wrong key
}

function stamp(ms) {
  return new Date(ms).toISOString().replace(/[-:]/g, '').replace('T', '-').replace(/\..*/, '') + '-' + String(ms % 1000).padStart(3, '0');
}

function createBackup(liveDb, reason = 'scheduled') {
  ensureDirs();
  const created = Date.now();
  const name = `backup-${stamp(created)}.db.enc`;
  const tmp = path.join(LOCAL_DIR, `.tmp-${created}.db`);
  try {
    liveDb.prepare('VACUUM INTO ?').run(tmp);                       // 1 consistent snapshot
    const plain = fs.readFileSync(tmp);
    const check = tableChecksum(liveDb);                            // 2 fingerprint
    const enc = encrypt(plain);                                     // 3 encrypt
    fs.writeFileSync(path.join(LOCAL_DIR, name), enc);
    const manifest = {
      file: name, created_at: new Date(created).toISOString(), created_ms: created, reason,
      algorithm: 'AES-256-GCM', records: check.count, table_sha256: check.sha256,
      sha256_plain: sha256(plain), sha256_encrypted: sha256(enc), size_bytes: enc.length,
    };                                                              // 4 manifest
    fs.writeFileSync(path.join(LOCAL_DIR, name + '.json'), JSON.stringify(manifest, null, 2));
    for (const f of [name, name + '.json']) {                       // 5 offsite, read-only
      const dst = path.join(OFFSITE_DIR, f);
      fs.copyFileSync(path.join(LOCAL_DIR, f), dst);
      fs.chmodSync(dst, 0o444);
    }
    prune();                                                        // 6 retention
    return manifest;
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

function readManifests(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.db.enc.json'))
    .map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')))
    .sort((a, b) => b.created_ms - a.created_ms);
}

function removeBackup(dir, file) {
  for (const f of [file, file + '.json']) {
    const p = path.join(dir, f);
    if (fs.existsSync(p)) { fs.chmodSync(p, 0o644); fs.rmSync(p); }
  }
}

function prune() {
  readManifests(LOCAL_DIR).slice(cfg.BACKUP_KEEP).forEach(m => removeBackup(LOCAL_DIR, m.file));
  const keepDays = new Set();
  const dayAgo = Date.now() - 24 * 3600 * 1000;
  for (const m of readManifests(OFFSITE_DIR)) {          // newest first -> first seen per day is kept
    if (m.created_ms > dayAgo) continue;                 // everything from the last 24 h is kept
    const day = m.created_at.slice(0, 10);
    if (keepDays.has(day) || keepDays.size >= 7) removeBackup(OFFSITE_DIR, m.file);
    else keepDays.add(day);
  }
}

function listBackups() {
  const offsite = new Set(readManifests(OFFSITE_DIR).map(m => m.file));
  return readManifests(LOCAL_DIR).map(m => ({ ...m, offsite: offsite.has(m.file) }));
}

// Newest backup taken strictly before `beforeMs` (e.g. the first attack alert).
function chooseKnownGood(beforeMs) {
  return listBackups().find(m => m.created_ms < beforeMs) || null;
}

// Returns which copy (local/offsite) is intact, verifying SHA-256 against the manifest.
function verifyBackup(file) {
  const result = { file, local: 'missing', offsite: 'missing' };
  for (const [where, dir] of [['local', LOCAL_DIR], ['offsite', OFFSITE_DIR]]) {
    const p = path.join(dir, file), mp = p + '.json';
    if (!fs.existsSync(p) || !fs.existsSync(mp)) continue;
    const m = JSON.parse(fs.readFileSync(mp, 'utf8'));
    result[where] = sha256(fs.readFileSync(p)) === m.sha256_encrypted ? 'ok' : 'HASH MISMATCH';
  }
  return result;
}

function restoreBackup(liveDb, file, { reason = 'manual' } = {}) {
  const t0 = Date.now();
  const steps = [];
  const step = (msg, ok = true) => steps.push({ t_ms: Date.now() - t0, ok, msg });

  // 2 verify hash; fall back to offsite copy if local is damaged/missing
  const v = verifyBackup(file);
  let dir;
  if (v.local === 'ok') { dir = LOCAL_DIR; step(`SHA-256 of local copy verified (${file})`); }
  else if (v.offsite === 'ok') {
    dir = OFFSITE_DIR;
    step(`Local copy ${v.local} - using offsite copy instead (3-2-1 rule)`, false);
    step('SHA-256 of offsite copy verified');
  } else throw Object.assign(new Error(`No intact copy of ${file} (local: ${v.local}, offsite: ${v.offsite})`), { steps });
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, file + '.json'), 'utf8'));

  // 3 decrypt
  const plain = decrypt(fs.readFileSync(path.join(dir, file)));
  step('Decrypted with AES-256-GCM (authentication tag valid - not tampered)');

  // 4 check plaintext + SQLite integrity + record count
  if (sha256(plain) !== manifest.sha256_plain) throw Object.assign(new Error('Plaintext hash mismatch'), { steps });
  const tmp = path.join(path.dirname(LOCAL_DIR), `.restore-${t0}.db`);
  fs.writeFileSync(tmp, plain);
  try {
    const bak = new Database(tmp, { readonly: true });
    const integrity = bak.pragma('integrity_check', { simple: true });
    const bakCheck = tableChecksum(bak);
    bak.close();
    if (integrity !== 'ok') throw new Error(`SQLite integrity_check failed: ${integrity}`);
    if (bakCheck.count !== manifest.records) throw new Error('Record count differs from manifest');
    step(`Integrity check ok, ${bakCheck.count} records match manifest`);

    // 5 replace live contents atomically
    const before = tableChecksum(liveDb);
    liveDb.prepare('ATTACH DATABASE ? AS bak').run(tmp);
    try {
      liveDb.transaction(() => {
        liveDb.exec('DELETE FROM main.employees; INSERT INTO main.employees SELECT * FROM bak.employees;');
      })();
    } finally { liveDb.exec('DETACH DATABASE bak'); }
    step(`Live table replaced in one transaction (${before.count} -> ${manifest.records} records)`);

    // 6 verify the live data is now byte-for-byte the backed-up data
    const after = tableChecksum(liveDb);
    if (after.sha256 !== manifest.table_sha256) throw new Error('Post-restore checksum does not match backup');
    step('Post-restore table checksum equals backup checksum - data recovered exactly');
  } catch (e) {
    e.steps = steps; throw e;
  } finally {
    fs.rmSync(tmp, { force: true });
  }

  // 7 RTO
  const duration = Date.now() - t0;
  const withinRto = duration <= cfg.RTO_TARGET_MS;
  step(`Restore took ${(duration / 1000).toFixed(2)} s - RTO target ${cfg.RTO_TARGET_MS / 60000} min ${withinRto ? 'MET' : 'MISSED'}`, withinRto);
  return { file, reason, backup_created_at: manifest.created_at, records: manifest.records,
    duration_ms: duration, rto_ms: cfg.RTO_TARGET_MS, within_rto: withinRto, steps };
}

module.exports = { createBackup, listBackups, verifyBackup, chooseKnownGood, restoreBackup, tableChecksum,
  LOCAL_DIR, OFFSITE_DIR, openCompany };
