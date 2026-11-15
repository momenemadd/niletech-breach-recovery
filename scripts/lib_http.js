'use strict';
// Tiny HTTP client for the simulation scripts: remembers the session cookie and sends a fake source IP
// through X-Forwarded-For (only honoured because SIMULATION_TRUST_XFF=true in .env).
const BASE = process.env.TARGET || 'http://localhost:3001';

function client(ip) {
  let cookie = '';
  async function call(method, path, body) {
    const res = await fetch(BASE + path, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip, ...(cookie ? { Cookie: cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const sc = res.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0];
    let data = null;
    try { data = await res.json(); } catch { /* not json */ }
    return { status: res.status, data };
  }
  return {
    ip,
    login: (username, password) => call('POST', '/api/login', { username, password }),
    logout: () => call('POST', '/api/logout'),
    get: p => call('GET', p),
    del: p => call('DELETE', p),
    post: (p, b) => call('POST', p, b),
  };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const now = () => new Date().toISOString().slice(11, 19);

module.exports = { client, sleep, now, BASE };
