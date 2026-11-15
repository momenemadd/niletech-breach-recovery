'use strict';
// Policy 2: structured, append-only security log. One JSON object per line.
// Fields: ts (ISO-8601 UTC), event, ip, username, result, detail.
// NEVER pass passwords, session ids or record contents to this function.
const fs = require('fs');
const path = require('path');
const cfg = require('../config');
const { abs } = require('./db');

const LOG_PATH = abs(cfg.LOG_FILE);
fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });

const ALLOWED = new Set(['LOGIN_FAIL', 'LOGIN_SUCCESS', 'LOGIN_BLOCKED', 'LOGIN_LOCKED', 'IP_BLOCKED',
  'ACCOUNT_LOCKED', 'ALERT', 'DATA_ACCESS', 'DATA_DELETE', 'BACKUP', 'RESTORE', 'ADMIN_ACTION', 'LOGOUT']);

function logEvent(event, { ip = null, username = null, result = null, detail = null, ts = Date.now() } = {}) {
  if (!ALLOWED.has(event)) throw new Error(`Unknown log event ${event}`);
  const line = JSON.stringify({ ts: new Date(ts).toISOString(), event, ip, username, result, detail });
  fs.appendFileSync(LOG_PATH, line + '\n');
}

module.exports = { logEvent, LOG_PATH };
