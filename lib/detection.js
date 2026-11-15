'use strict';
// Policy 3 detection rules, evaluated in real time on every login.
//   R1 Brute force     : >= R1_FAIL_THRESHOLD failed logins from one IP inside R1_WINDOW_MS      -> High
//   R2 Password spray  : >= R2_USER_THRESHOLD different usernames failing from one IP           -> Medium
//   R3 Probable breach : R1 fired for an IP, then a SUCCESSFUL login from that IP within
//                        R3_SUCCESS_WINDOW_MS                                                   -> Critical
// Mitigation depends on protection mode:
//   on  -> R1 blocks the IP (60 s, doubling each repeat); R3 refuses the login and locks the account
//   off -> alerts only (the vulnerable system), so the breach can happen and be recovered from
const cfg = require('../config');
const { logEvent } = require('./logger');

function createDetector(db, { onAlert = () => {}, getMode = () => cfg.PROTECTION_MODE } = {}) {
  const q = {
    insertAttempt: db.prepare('INSERT INTO attempts (ts, ip, username, status) VALUES (?, ?, ?, ?)'),
    failsByIp: db.prepare("SELECT COUNT(*) AS n FROM attempts WHERE ip = ? AND status = 'failed' AND ts > ?"),
    usersByIp: db.prepare("SELECT COUNT(DISTINCT username) AS n FROM attempts WHERE ip = ? AND status = 'failed' AND ts > ?"),
    lastAlert: db.prepare('SELECT * FROM alerts WHERE rule = ? AND ip = ? AND ts > ? ORDER BY ts DESC LIMIT 1'),
    insertAlert: db.prepare('INSERT INTO alerts (ts, rule, severity, ip, username, message) VALUES (?, ?, ?, ?, ?, ?)'),
    getBlock: db.prepare('SELECT * FROM blocked_ips WHERE ip = ?'),
    upsertBlock: db.prepare(`INSERT INTO blocked_ips (ip, blocked_at, unblock_at, reason, block_count)
       VALUES (@ip, @now, @until, @reason, 1)
       ON CONFLICT(ip) DO UPDATE SET blocked_at=@now, unblock_at=@until, reason=@reason, block_count=block_count+1`),
    lockUser: db.prepare('UPDATE users SET locked = 1, locked_reason = ? WHERE username = ?'),
  };

  function raise(rule, severity, ip, username, message, now) {
    const info = q.insertAlert.run(now, rule, severity, ip, username, message);
    logEvent('ALERT', { ts: now, ip, username, result: severity, detail: `${rule}: ${message}` });
    onAlert({ id: info.lastInsertRowid, ts: now, rule, severity, ip, username, message });
  }

  function isBlocked(ip, now = Date.now()) {
    const b = q.getBlock.get(ip);
    return b && b.unblock_at > now ? b : null;
  }

  function blockIp(ip, now) {
    const prev = q.getBlock.get(ip);
    const count = prev ? prev.block_count + 1 : 1;
    const duration = cfg.BLOCK_BASE_MS * Math.pow(2, count - 1);
    q.upsertBlock.run({ ip, now, until: now + duration, reason: `R1 brute force (block #${count})` });
    logEvent('IP_BLOCKED', { ts: now, ip, result: 'blocked', detail: `duration ${Math.round(duration / 1000)}s, block #${count}` });
    return duration;
  }

  function recordAttempt(ip, username, status, now = Date.now()) {
    q.insertAttempt.run(now, ip, username, status);
  }

  // Called after a failed password. Returns { blocked, duration }.
  function afterFailure(ip, username, now = Date.now()) {
    const out = { blocked: false };
    const fails = q.failsByIp.get(ip, now - cfg.R1_WINDOW_MS).n;
    if (fails >= cfg.R1_FAIL_THRESHOLD) {
      if (!q.lastAlert.get('R1', ip, now - cfg.R1_WINDOW_MS)) {
        raise('R1', 'High', ip, username,
          `${fails} failed logins from ${ip} within ${cfg.R1_WINDOW_MS / 60000} min (threshold ${cfg.R1_FAIL_THRESHOLD})`, now);
      }
      if (getMode() === 'on' && !isBlocked(ip, now)) {
        out.blocked = true;
        out.duration = blockIp(ip, now);
      }
    }
    const users = q.usersByIp.get(ip, now - cfg.R2_WINDOW_MS).n;
    if (users >= cfg.R2_USER_THRESHOLD && !q.lastAlert.get('R2', ip, now - cfg.R2_WINDOW_MS)) {
      raise('R2', 'Medium', ip, username, `${users} different usernames failed from ${ip} (possible password spray)`, now);
    }
    return out;
  }

  // Called after a correct password, BEFORE the session is created.
  // Returns { breach, deny }. deny = true means do not log the user in.
  function afterSuccess(ip, username, now = Date.now()) {
    const r1 = q.lastAlert.get('R1', ip, now - cfg.R3_SUCCESS_WINDOW_MS);
    if (!r1) return { breach: false, deny: false };
    const secs = Math.round((now - r1.ts) / 1000);
    const ago = secs < 120 ? `${secs} s` : `${Math.round(secs / 60)} min`;
    const mode = getMode();
    const action = mode === 'on'
      ? 'login refused, account locked, password reset required'
      : 'PROTECTION OFF - attacker is logged in, start incident response';
    raise('R3', 'Critical', ip, username,
      `Successful login as "${username}" from ${ip} ${ago} after brute-force alert - ${action}`, now);
    if (mode === 'on') {
      q.lockUser.run(`R3 probable breach from ${ip}`, username);
      logEvent('ACCOUNT_LOCKED', { ts: now, ip, username, result: 'locked', detail: 'R3 probable breach' });
      return { breach: true, deny: true };
    }
    return { breach: true, deny: false };
  }

  return { isBlocked, recordAttempt, afterFailure, afterSuccess };
}

module.exports = { createDetector };
