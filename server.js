'use strict';
// NileTech breach detection & recovery app.
// Based on singh-70-9-shreyansh/waf-bruteforce-detection (MIT) - rebuilt on SQLite, with bcrypt + roles,
// structured logging, rules R1-R3, a sensitive-records page and encrypted backup/restore.
const http = require('http');
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');

const cfg = require('./config');
const { openSecurity, openCompany } = require('./lib/db');
const { logEvent } = require('./lib/logger');
const { createDetector } = require('./lib/detection');
const backup = require('./lib/backup');
const { checkPassword } = require('./lib/passwords');

if (!cfg.SESSION_SECRET || !cfg.BACKUP_KEY_HEX) {
  console.error('Missing SESSION_SECRET / BACKUP_KEY. Run "npm run setup" first.');
  process.exit(1);
}

const sec = openSecurity();
const company = openCompany();

// ---------- settings (protection mode survives restarts) ----------
const getSetting = (k, d) => (sec.prepare('SELECT value FROM settings WHERE key = ?').get(k) || { value: d }).value;
const setSetting = (k, v) => sec.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
if (!sec.prepare("SELECT 1 FROM settings WHERE key = 'protection_mode'").get()) setSetting('protection_mode', cfg.PROTECTION_MODE);
const getMode = () => getSetting('protection_mode', 'on');

// ---------- app ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server);
let maintenance = false;

app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {                       // basic security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:",
  });
  next();
});

const sessionMw = session({
  name: 'sid',
  secret: cfg.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,                                   // idle timeout: each request extends the session
  cookie: { httpOnly: true, sameSite: 'strict', maxAge: cfg.SESSION_IDLE_MS },
});
app.use(sessionMw);

function clientIp(req) {
  if (cfg.SIMULATION_TRUST_XFF && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return String(req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

// ---------- live dashboard push (admins only, throttled) ----------
io.engine.use(sessionMw);
io.on('connection', socket => {
  const u = socket.request.session && socket.request.session.user;
  if (!u || u.role !== 'admin') return socket.disconnect(true);
  socket.join('admins');
  socket.emit('update', dashboardState());
});
let pushTimer = null;
function pushUpdate() {
  if (pushTimer) return;
  pushTimer = setTimeout(() => { pushTimer = null; io.to('admins').emit('update', dashboardState()); }, 300);
}

const detector = createDetector(sec, {
  getMode,
  onAlert: alert => io.to('admins').emit('alert', alert),
});

// ---------- auth helpers ----------
const getUser = sec.prepare('SELECT * FROM users WHERE username = ?');
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

function requireRole(...roles) {
  return (req, res, next) => {
    const s = req.session && req.session.user;
    if (!s) return res.status(401).json({ error: 'Not logged in' });
    const u = getUser.get(s.username);
    if (!u || u.locked) {                           // R3 lock kills existing sessions too
      return req.session.destroy(() => res.status(401).json({ error: 'Account locked - contact the security admin' }));
    }
    if (!roles.includes(u.role)) return res.status(403).json({ error: 'Forbidden for your role' });
    req.user = u;
    next();
  };
}
function requirePage(role) {
  return (req, res, next) => {
    const s = req.session && req.session.user;
    const u = s && getUser.get(s.username);
    if (!u || u.locked || u.role !== role) return res.redirect('/');
    next();
  };
}

// ---------- pages (protected before static) ----------
app.get('/dashboard.html', requirePage('admin'));
app.get('/records.html', requirePage('hr'));
app.get('/home.html', (req, res, next) => (req.session.user ? next() : res.redirect('/')));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vendor', express.static(path.join(__dirname, 'node_modules', 'chart.js', 'dist')));  // served locally: demo works offline

// ---------- login / logout ----------
app.post('/api/login', async (req, res) => {
  const ip = clientIp(req);
  const username = String((req.body && req.body.username) || '').trim().slice(0, 64);
  const password = String((req.body && req.body.password) || '');
  const now = Date.now();

  const block = detector.isBlocked(ip, now);
  if (block) {
    detector.recordAttempt(ip, username, 'blocked', now);
    logEvent('LOGIN_BLOCKED', { ts: now, ip, username, result: 'blocked' });
    pushUpdate();
    return res.status(429).json({ status: 'blocked', retry_after_s: Math.ceil((block.unblock_at - now) / 1000) });
  }

  const user = getUser.get(username);
  if (user && user.locked) {
    detector.recordAttempt(ip, username, 'locked', now);
    logEvent('LOGIN_LOCKED', { ts: now, ip, username, result: 'locked' });
    pushUpdate();
    return res.status(423).json({ status: 'locked', message: 'Account locked - contact the security admin' });
  }

  // compare even for unknown users so response time does not reveal valid usernames
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH) && !!user;

  if (!ok) {
    detector.recordAttempt(ip, username, 'failed', now);
    logEvent('LOGIN_FAIL', { ts: now, ip, username, result: 'failed' });   // note: password NOT logged
    const r = detector.afterFailure(ip, username, now);
    pushUpdate();
    return res.status(401).json({ status: 'failed', blocked: r.blocked });
  }

  const r3 = detector.afterSuccess(ip, username, now);
  detector.recordAttempt(ip, username, r3.deny ? 'success_denied' : 'success', now);
  logEvent('LOGIN_SUCCESS', { ts: now, ip, username, result: r3.deny ? 'denied_r3' : 'ok' });
  pushUpdate();
  if (r3.deny) return res.status(423).json({ status: 'locked', message: 'Suspicious login - account locked' });

  req.session.regenerate(err => {                   // new session id on login (prevents fixation)
    if (err) return res.status(500).json({ error: 'session error' });
    req.session.user = { username: user.username, role: user.role, ip };
    const redirect = user.role === 'admin' ? '/dashboard.html' : user.role === 'hr' ? '/records.html' : '/home.html';
    res.json({ status: 'success', role: user.role, redirect });
  });
});

app.post('/api/logout', (req, res) => {
  const u = req.session.user;
  if (u) logEvent('LOGOUT', { ip: clientIp(req), username: u.username, result: 'ok' });
  req.session.destroy(() => { res.clearCookie('sid'); res.json({ success: true }); });
});

app.get('/api/me', requireRole('employee', 'hr', 'admin'), (req, res) =>
  res.json({ username: req.user.username, role: req.user.role }));

// ---------- sensitive records (Confidential, HR only) ----------
const mask = id => '*'.repeat(Math.max(0, id.length - 4)) + id.slice(-4);
function notInMaintenance(req, res, next) {
  if (maintenance) return res.status(503).json({ error: 'Maintenance - data is being restored' });
  next();
}

app.get('/api/records', requireRole('hr'), notInMaintenance, (req, res) => {
  const rows = company.prepare('SELECT * FROM employees ORDER BY id').all()
    .map(r => ({ ...r, national_id: mask(r.national_id) }));
  logEvent('DATA_ACCESS', { ip: clientIp(req), username: req.user.username, result: 'ok', detail: `read ${rows.length} employee records` });
  pushUpdate();
  res.json(rows);
});

app.delete('/api/records/:id', requireRole('hr'), notInMaintenance, (req, res) => {
  const info = company.prepare('DELETE FROM employees WHERE id = ?').run(Number(req.params.id));
  logEvent('DATA_DELETE', { ip: clientIp(req), username: req.user.username, result: info.changes ? 'ok' : 'not_found', detail: `employee id ${Number(req.params.id)}` });
  pushUpdate();
  res.json({ deleted: info.changes });
});

// ---------- admin / SOC ----------
function dashboardState() {
  const now = Date.now();
  return {
    now,
    mode: getMode(),
    maintenance,
    thresholds: { r1: cfg.R1_FAIL_THRESHOLD, r1_window_min: cfg.R1_WINDOW_MS / 60000, r3_window_min: cfg.R3_SUCCESS_WINDOW_MS / 60000, block_base_s: cfg.BLOCK_BASE_MS / 1000 },
    attempts: sec.prepare('SELECT * FROM attempts ORDER BY id DESC LIMIT 300').all(),
    blocked: sec.prepare('SELECT * FROM blocked_ips WHERE unblock_at > ? ORDER BY blocked_at DESC').all(now),
    alerts: sec.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 200').all(),
    locked: sec.prepare('SELECT username, role, locked_reason FROM users WHERE locked = 1').all(),
    records: company.prepare('SELECT COUNT(*) AS n FROM employees').get().n,
    backups: backup.listBackups().slice(0, 10),
  };
}
const admin = requireRole('admin');
const adminLog = (req, detail) => logEvent('ADMIN_ACTION', { ip: clientIp(req), username: req.user.username, result: 'ok', detail });

app.get('/api/state', admin, (req, res) => res.json(dashboardState()));

app.post('/api/mode', admin, (req, res) => {
  const mode = req.body.mode === 'off' ? 'off' : 'on';
  setSetting('protection_mode', mode);
  adminLog(req, `protection mode -> ${mode}`);
  pushUpdate();
  res.json({ mode });
});

app.post('/api/unblock', admin, (req, res) => {
  const ip = String(req.body.ip || '');
  sec.prepare('UPDATE blocked_ips SET unblock_at = ? WHERE ip = ?').run(Date.now(), ip);
  adminLog(req, `unblocked IP ${ip}`);
  pushUpdate();
  res.json({ success: true });
});

app.post('/api/alerts/ack', admin, (req, res) => {
  const id = req.body.id;
  if (id === 'all') sec.prepare('UPDATE alerts SET acknowledged = 1').run();
  else sec.prepare('UPDATE alerts SET acknowledged = 1 WHERE id = ?').run(Number(id));
  adminLog(req, `acknowledged alert ${id}`);
  pushUpdate();
  res.json({ success: true });
});

// Containment (incident response step 1): block the attacker IP for 1 h and lock the account,
// which also kills any live session of that account on its next request.
app.post('/api/contain', admin, (req, res) => {
  const ip = String(req.body.ip || ''), username = String(req.body.username || '');
  const now = Date.now();
  if (ip) {
    sec.prepare(`INSERT INTO blocked_ips (ip, blocked_at, unblock_at, reason, block_count) VALUES (?, ?, ?, 'Manual containment', 1)
      ON CONFLICT(ip) DO UPDATE SET blocked_at = excluded.blocked_at, unblock_at = excluded.unblock_at, reason = excluded.reason`)
      .run(ip, now, now + 60 * 60 * 1000);
    logEvent('IP_BLOCKED', { ip, username: req.user.username, result: 'blocked', detail: 'manual containment, 1 h' });
  }
  if (username) {
    sec.prepare("UPDATE users SET locked = 1, locked_reason = 'Manual containment after breach' WHERE username = ?").run(username);
    logEvent('ACCOUNT_LOCKED', { ip, username, result: 'locked', detail: `manual containment by ${req.user.username}` });
  }
  adminLog(req, `contained ip=${ip} user=${username}`);
  pushUpdate();
  res.json({ success: true });
});

// Unlock = forced password reset: the admin must set a new password that meets Policy 1.
app.post('/api/users/unlock', admin, (req, res) => {
  const username = String(req.body.username || '');
  const pw = String(req.body.newPassword || '');
  const check = checkPassword(pw, username);
  if (!check.ok) return res.status(400).json({ error: 'Password needs ' + check.problems.join(', ') });
  const info = sec.prepare('UPDATE users SET locked = 0, locked_reason = NULL, password_hash = ? WHERE username = ?')
    .run(bcrypt.hashSync(pw, 12), username);
  if (!info.changes) return res.status(404).json({ error: 'No such user' });
  adminLog(req, `unlocked ${username} with forced password reset`);
  pushUpdate();
  res.json({ success: true });
});

// ---------- backup & restore ----------
app.post('/api/backup', admin, (req, res) => {
  try {
    const m = backup.createBackup(company, 'manual');
    logEvent('BACKUP', { ip: clientIp(req), username: req.user.username, result: 'ok', detail: `${m.file} (${m.records} records)` });
    pushUpdate();
    res.json(m);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/backups/verify', admin, (req, res) => res.json(backup.listBackups().map(m => backup.verifyBackup(m.file))));

// Known-good point = newest backup taken BEFORE the first unacknowledged attack alert (R1/R3).
function restorePlan() {
  const first = sec.prepare("SELECT * FROM alerts WHERE rule IN ('R1','R3') AND acknowledged = 0 ORDER BY ts ASC LIMIT 1").get();
  const all = backup.listBackups();
  if (!first) return { attack_started: null, chosen: all[0] || null, why: 'No open attack alerts - newest backup' };
  const chosen = backup.chooseKnownGood(first.ts);
  return {
    attack_started: new Date(first.ts).toISOString(),
    chosen,
    skipped: all.filter(m => m.created_ms >= first.ts).map(m => m.file),
    why: chosen ? 'Newest backup taken before the first attack alert (backups after it may contain attacker changes)'
                : 'No backup exists from before the attack!',
  };
}
app.get('/api/restore/plan', admin, (req, res) => res.json(restorePlan()));

app.post('/api/restore', admin, (req, res) => {
  const plan = restorePlan();
  const file = req.body.file || (plan.chosen && plan.chosen.file);
  if (!file) return res.status(400).json({ error: 'No suitable backup' });
  maintenance = true;                                  // step 1 isolate: records API returns 503
  pushUpdate();
  try {
    const report = backup.restoreBackup(company, file, { reason: req.body.file ? 'manual choice' : 'known-good' });
    logEvent('RESTORE', { ip: clientIp(req), username: req.user.username, result: report.within_rto ? 'ok' : 'rto_missed',
      detail: `${file} -> ${report.records} records in ${report.duration_ms} ms` });
    res.json(report);
  } catch (e) {
    logEvent('RESTORE', { ip: clientIp(req), username: req.user.username, result: 'failed', detail: e.message });
    res.status(500).json({ error: e.message, steps: e.steps || [] });
  } finally {
    maintenance = false;
    pushUpdate();
  }
});

// ---------- scheduled backups (Policy 5: hourly, RPO 1 h) ----------
function scheduledBackup(reason) {
  try {
    const m = backup.createBackup(company, reason);
    logEvent('BACKUP', { result: 'ok', detail: `${reason}: ${m.file} (${m.records} records)` });
    console.log(`[backup] ${reason}: ${m.file} (${m.records} records)`);
    pushUpdate();
  } catch (e) { console.error('[backup] failed', e.message); logEvent('BACKUP', { result: 'failed', detail: e.message }); }
}
const newest = backup.listBackups()[0];
if (!newest || Date.now() - newest.created_ms > cfg.BACKUP_INTERVAL_MS) scheduledBackup('startup');
setInterval(() => scheduledBackup('scheduled'), cfg.BACKUP_INTERVAL_MS).unref();

server.listen(cfg.PORT, () => {
  console.log(`NileTech app on http://localhost:${cfg.PORT}  |  protection mode: ${getMode().toUpperCase()}`);
});
