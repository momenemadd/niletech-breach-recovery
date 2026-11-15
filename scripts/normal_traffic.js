'use strict';
// Normal (benign) traffic generator.
// Employees log in from office IPs, sometimes mistype their password once or twice (never 5 times),
// HR opens the records page, everyone logs out. This is the baseline that must NOT trigger alerts.
//   node scripts/normal_traffic.js [--sessions 30] [--delay 800]
const { client, sleep, now } = require('./lib_http');

const args = process.argv.slice(2);
const opt = (k, d) => (args.includes(k) ? Number(args[args.indexOf(k) + 1]) : d);
const SESSIONS = opt('--sessions', 30);
const DELAY = opt('--delay', 800);

const PEOPLE = [
  { u: 'a.hassan', pw: 'Ah#91-Blue-Kite', ip: '10.0.0.21' },
  { u: 'm.farouk', pw: 'Mf$58-Red-Lamp', ip: '10.0.0.22' },
  { u: 's.nabil', pw: 'Sn%23-Gold-Tree', ip: '10.0.0.23' },
  { u: 'n.adel', pw: 'Na&64-Grey-Boat', ip: '10.0.0.24' },
  { u: 'k.samir', pw: 'Ks*37-Pink-Moon', ip: '41.33.120.7' },      // works from home
  { u: 'hr.manager', pw: 'Summer@2026', ip: '10.0.0.15', hr: true },
];
const typo = pw => pw.slice(0, -1) + (pw.endsWith('e') ? 'x' : 'e');

(async () => {
  let ok = 0, typos = 0;
  const perIp = {};
  console.log(`[${now()}] Normal traffic: ${SESSIONS} user sessions`);
  for (let i = 0; i < SESSIONS; i++) {
    const p = PEOPLE[Math.floor(Math.random() * PEOPLE.length)];
    const c = client(p.ip);
    let mistakes = Math.random() < 0.25 ? (Math.random() < 0.3 ? 2 : 1) : 0;     // realistic typos: 0-2
    // keep each IP at <= 3 typos per run: real users rarely fail more, and it stays under R1's 5
    mistakes = Math.min(mistakes, 3 - (perIp[p.ip] || 0));
    perIp[p.ip] = (perIp[p.ip] || 0) + mistakes;
    for (let t = 0; t < mistakes; t++) {
      await c.login(p.u, typo(p.pw)); typos++;
      console.log(`[${now()}] ${p.ip.padEnd(13)} ${p.u.padEnd(11)} typo -> failed`);
      await sleep(DELAY / 2);
    }
    const r = await c.login(p.u, p.pw);
    console.log(`[${now()}] ${p.ip.padEnd(13)} ${p.u.padEnd(11)} login -> ${r.data && r.data.status}`);
    if (r.data && r.data.status === 'success') {
      ok++;
      if (p.hr) {
        const rec = await c.get('/api/records');
        console.log(`[${now()}] ${p.ip.padEnd(13)} ${p.u.padEnd(11)} viewed ${Array.isArray(rec.data) ? rec.data.length : 0} records`);
      }
      await sleep(DELAY);
      await c.logout();
    }
    await sleep(DELAY);
  }
  console.log(`[${now()}] Done: ${ok} successful sessions, ${typos} typos. Expect: no R1/R3 alerts.`);
})().catch(e => { console.error('Is the server running? ', e.message); process.exit(1); });
