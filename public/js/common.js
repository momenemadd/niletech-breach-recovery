'use strict';
// Shared helpers. All dynamic text goes through textContent / el() - never innerHTML with data -
// which fixes the XSS hole in the original dashboard (a username like <img onerror=...> ran as code).
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) n.setAttribute(k, v);
  }
  for (const c of children.flat()) n.append(c instanceof Node ? c : document.createTextNode(c == null ? '' : String(c)));
  return n;
}
async function api(method, url, body) {
  const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (res.status === 401) { location.href = '/'; throw new Error('logged out'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { data });
  return data;
}
const fmtTime = ms => new Date(ms).toLocaleTimeString();
const fmtDate = ms => new Date(ms).toLocaleString();

document.addEventListener('DOMContentLoaded', async () => {
  const who = document.getElementById('who');
  if (who) { try { const me = await api('GET', '/api/me'); who.textContent = `${me.username} (${me.role})`; } catch {} }
  const lo = document.getElementById('btnLogout');
  if (lo) lo.addEventListener('click', async () => { await api('POST', '/api/logout'); location.href = '/'; });
});
