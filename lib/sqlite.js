'use strict';
// Thin wrapper over Node's BUILT-IN SQLite (node:sqlite, Node 22.13+), so there is no native module to
// compile on Windows. Exposes the few helpers the project uses: pragma(), transaction().
let DatabaseSync;
const emitWarning = process.emitWarning;               // hide the "SQLite is experimental" notice
process.emitWarning = (w, ...rest) => (String(w).includes('SQLite') ? undefined : emitWarning.call(process, w, ...rest));
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch {
  console.error(`This project needs Node.js 22.13 or newer (built-in SQLite). You have ${process.version}.\n` +
    'Install the current LTS from https://nodejs.org and run again.');
  process.exit(1);
}

class Database {
  constructor(file, { readonly = false } = {}) {
    this.db = new DatabaseSync(file, { readOnly: readonly });
  }
  exec(sql) { return this.db.exec(sql); }
  prepare(sql) { return this.db.prepare(sql); }
  close() { this.db.close(); }
  // pragma('journal_mode = WAL')  |  pragma('integrity_check', { simple: true }) -> 'ok'
  pragma(p, { simple = false } = {}) {
    const rows = this.db.prepare(`PRAGMA ${p}`).all();
    return simple ? (rows[0] ? Object.values(rows[0])[0] : undefined) : rows;
  }
  // transaction(fn)() runs fn inside BEGIN/COMMIT, rolling back on error (all-or-nothing)
  transaction(fn) {
    return (...args) => {
      this.db.exec('BEGIN IMMEDIATE');
      try { const r = fn(...args); this.db.exec('COMMIT'); return r; }
      catch (e) { this.db.exec('ROLLBACK'); throw e; }
    };
  }
}

module.exports = Database;
