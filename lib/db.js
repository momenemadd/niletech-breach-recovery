'use strict';
// Two separate SQLite databases on purpose:
//   security.db - users, login attempts, alerts, blocks  (Internal; evidence - never rolled back)
//   company.db  - sensitive employee records            (Confidential; this is what we back up/restore)
// Keeping them apart means a restore brings back the company data without erasing the
// attack evidence or un-locking a compromised account.
const path = require('path');
const fs = require('fs');
const Database = require('./sqlite');
const cfg = require('../config');

const ROOT = path.join(__dirname, '..');
const abs = p => (path.isAbsolute(p) ? p : path.join(ROOT, p));
const DATA_DIR = abs(cfg.DATA_DIR);
fs.mkdirSync(DATA_DIR, { recursive: true });

const SECURITY_DB_PATH = path.join(DATA_DIR, 'security.db');
const COMPANY_DB_PATH = path.join(DATA_DIR, 'company.db');

function openSecurity() {
  const db = new Database(SECURITY_DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('employee','hr','admin')),
      locked INTEGER NOT NULL DEFAULT 0,
      locked_reason TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL, ip TEXT NOT NULL, username TEXT, status TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts ON attempts(ip, ts);
    CREATE TABLE IF NOT EXISTS blocked_ips (
      ip TEXT PRIMARY KEY, blocked_at INTEGER, unblock_at INTEGER, reason TEXT, block_count INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL,
      ip TEXT, username TEXT, message TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
  `);
  return db;
}

function openCompany(file = COMPANY_DB_PATH) {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY,
      full_name TEXT NOT NULL, national_id TEXT NOT NULL, department TEXT NOT NULL,
      salary INTEGER NOT NULL, phone TEXT, email TEXT
    );
  `);
  return db;
}

module.exports = { ROOT, abs, DATA_DIR, SECURITY_DB_PATH, COMPANY_DB_PATH, openSecurity, openCompany };
