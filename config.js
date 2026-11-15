'use strict';
// Central configuration. Every threshold here is referenced by the Security Policies doc
// (Policy 1, 3 and 5), so change it here and the whole system follows.
require('dotenv').config({ quiet: true, path: require('path').join(__dirname, '.env') });

const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? process.env[k] : d);
const num = (k, d) => Number(env(k, d));

module.exports = {
  PORT: num('PORT', 3001),

  // --- Policy 1: authentication / lockout ---
  SESSION_SECRET: env('SESSION_SECRET', null),
  SESSION_IDLE_MS: num('SESSION_IDLE_MS', 30 * 60 * 1000),   // 30 min idle timeout
  PASSWORD_MIN_LENGTH: 10,

  // --- Policy 3: detection rules ---
  R1_FAIL_THRESHOLD: num('R1_FAIL_THRESHOLD', 5),              // >= 5 failed logins ...
  R1_WINDOW_MS: num('R1_WINDOW_MS', 5 * 60 * 1000),            // ... from one IP within 5 min
  R2_USER_THRESHOLD: num('R2_USER_THRESHOLD', 3),              // >= 3 different usernames from one IP
  R2_WINDOW_MS: num('R2_WINDOW_MS', 5 * 60 * 1000),
  R3_SUCCESS_WINDOW_MS: num('R3_SUCCESS_WINDOW_MS', 10 * 60 * 1000), // success within 10 min after R1
  BLOCK_BASE_MS: num('BLOCK_BASE_MS', 60 * 1000),              // first block 60 s, doubles each repeat

  // "on"  = detect + automatically block IPs / lock accounts (hardened system)
  // "off" = detect + alert only (the vulnerable system, used to show the breach + recovery)
  PROTECTION_MODE: env('PROTECTION_MODE', 'on'),

  // Simulation only: lets the traffic scripts pretend to come from many IPs via X-Forwarded-For.
  // NEVER enable on a real deployment - attackers could spoof their IP.
  SIMULATION_TRUST_XFF: env('SIMULATION_TRUST_XFF', 'true') === 'true',

  // --- Policy 5: backup & recovery ---
  BACKUP_KEY_HEX: env('BACKUP_KEY', null),                     // 32-byte AES-256 key, hex
  BACKUP_INTERVAL_MS: num('BACKUP_INTERVAL_MS', 60 * 60 * 1000), // hourly (RPO = 1 h)
  BACKUP_KEEP: num('BACKUP_KEEP', 24),                         // keep the newest 24 backups
  RTO_TARGET_MS: num('RTO_TARGET_MS', 15 * 60 * 1000),         // restore must finish < 15 min
  RPO_TARGET_MS: num('RPO_TARGET_MS', 60 * 60 * 1000),

  // --- Paths ---
  DATA_DIR: env('DATA_DIR', 'data'),
  LOG_FILE: env('LOG_FILE', 'logs/auth.log'),
  BACKUP_DIR: env('BACKUP_DIR', 'backups/local'),
  OFFSITE_DIR: env('OFFSITE_DIR', 'backups/offsite'),
};
