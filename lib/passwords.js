'use strict';
// Policy 1 password rules. Complexity alone is not enough (e.g. "Summer@2026" passes it but is in every
// wordlist), so we also reject passwords built from common words + years - the hardening lesson of the breach.
const cfg = require('../config');

const COMMON = ['password', 'welcome', 'summer', 'winter', 'spring', 'autumn', 'admin', 'qwerty', 'letmein',
  'company', 'niletech', 'egypt', 'cairo', '123456', 'iloveyou', 'monkey', 'dragon'];

function checkPassword(pw, username = '') {
  const problems = [];
  if (typeof pw !== 'string' || pw.length < cfg.PASSWORD_MIN_LENGTH) problems.push(`at least ${cfg.PASSWORD_MIN_LENGTH} characters`);
  if (!/[A-Z]/.test(pw)) problems.push('an uppercase letter');
  if (!/[a-z]/.test(pw)) problems.push('a lowercase letter');
  if (!/[0-9]/.test(pw)) problems.push('a digit');
  if (!/[^A-Za-z0-9]/.test(pw)) problems.push('a symbol');
  const lower = String(pw).toLowerCase();
  if (COMMON.some(w => lower.includes(w))) problems.push('no common words (e.g. "summer", "welcome", "password")');
  if (username && lower.includes(username.toLowerCase().split('.')[0])) problems.push('no part of the username');
  return { ok: problems.length === 0, problems };
}

module.exports = { checkPassword };
