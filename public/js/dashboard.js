'use strict';
const $ = id => document.getElementById(id);
let state = null, chart = null, verify = {};

// ---------- rendering ----------
function render(s) {
  state = s;
  const on = s.mode === 'on';
  $('modePill').textContent = on ? 'PROTECTION ON' : 'PROTECTION OFF';
  $('modePill').className = 'pill ' + (on ? 'on' : 'off');
  $('btnMode').textContent = on ? 'Turn protection OFF' : 'Turn protection ON';
  $('maintPill').classList.toggle('hidden', !s.maintenance);
  const t = s.thresholds;
  $('thresholds').textContent = `R1: ${t.r1} fails / ${t.r1_window_min} min  |  R3: success within ${t.r3_window_min} min  |  block ${t.block_base_s}s x2`;

  const failed5 = s.attempts.filter(a => a.status === 'failed' && a.ts > s.now - 5 * 60000).length;
  const open = s.alerts.filter(a => !a.acknowledged);
  kpi('kFailed', failed5, failed5 >= t.r1);
  kpi('kBlocked', s.blocked.length, s.blocked.length > 0);
  kpi('kAlerts', open.length, open.some(a => a.severity === 'Critical'));
  const baseline = s.backups.length ? s.backups[s.backups.length - 1].records : s.records;
  kpi('kRecords', s.records, s.records < baseline);

  renderAlerts(s.alerts);
  renderAttempts(s.attempts);
  renderBlocked(s.blocked);
  renderLocked(s.locked);
  renderBackups(s.backups);
  renderChart(s.attempts, s.now);
  loadPlan();
}
function kpi(id, v, bad) { $(id).querySelector('.value').textContent = v; $(id).classList.toggle('bad', !!bad); }

function renderAlerts(alerts) {
  if (!alerts.length) return $('alerts').replaceChildren(el('div', { class: 'empty' }, 'No alerts'));
  $('alerts').replaceChildren(...alerts.map(a => el('div', { class: `alert ${a.severity}${a.acknowledged ? ' acked' : ''}` },
    el('div', { class: 'body' },
      el('div', { class: 'meta' }, el('span', { class: `sev ${a.severity}` }, `${a.severity} - ${a.rule}`), `  ${fmtTime(a.ts)}  ${a.ip || ''}  ${a.username || ''}`),
      el('div', {}, a.message)),
    a.rule === 'R3' && !a.acknowledged
      ? el('button', { class: 'small danger', onclick: () => api('POST', '/api/contain', { ip: a.ip, username: a.username }).then(() => toast(`Contained: ${a.ip} blocked 1 h, ${a.username} locked`, false)) }, 'Contain')
      : '',
    a.acknowledged ? '' : el('button', { class: 'small secondary', onclick: () => api('POST', '/api/alerts/ack', { id: a.id }) }, 'Ack'))));
}
function renderAttempts(list) {
  $('attempts').replaceChildren(...list.map(a => el('tr', {},
    el('td', {}, fmtTime(a.ts)), el('td', {}, a.ip), el('td', {}, a.username), el('td', { class: 'st-' + a.status }, a.status))));
}
function renderBlocked(list) {
  if (!list.length) return $('blocked').replaceChildren(el('tr', {}, el('td', { colspan: 4, class: 'empty' }, 'No blocked IPs')));
  $('blocked').replaceChildren(...list.map(b => el('tr', {},
    el('td', {}, b.ip), el('td', {}, b.reason), el('td', {}, fmtTime(b.unblock_at)),
    el('td', {}, el('button', { class: 'small secondary', onclick: () => api('POST', '/api/unblock', { ip: b.ip }) }, 'Unblock')))));
}
function renderLocked(list) {
  if (!list.length) return $('locked').replaceChildren(el('tr', {}, el('td', { colspan: 3, class: 'empty' }, 'No locked accounts')));
  $('locked').replaceChildren(...list.map(u => {
    const input = el('input', { type: 'password', placeholder: 'new password' });
    const go = async () => {
      try { await api('POST', '/api/users/unlock', { username: u.username, newPassword: input.value }); toast(`${u.username} unlocked with new password`, false); }
      catch (e) { toast(e.message, true); }
    };
    return el('tr', {}, el('td', {}, u.username), el('td', {}, u.locked_reason || ''),
      el('td', {}, el('div', { class: 'inline-form' }, input, el('button', { class: 'small', onclick: go }, 'Reset & unlock'))));
  }));
}
function renderBackups(list) {
  $('backups').replaceChildren(...list.map(b => {
    const v = verify[b.file] || {};
    const cell = s => el('td', { class: s === 'ok' ? 'st-success' : s ? 'st-failed' : '' }, s || (b.offsite ? '...' : ''));
    return el('tr', {}, el('td', {}, fmtDate(b.created_ms)), el('td', {}, b.reason), el('td', { class: 'num' }, b.records), cell(v.local), cell(v.offsite));
  }));
}
function renderChart(attempts, now) {
  const labels = [], failed = [], ok = [], blocked = [];
  for (let i = 29; i >= 0; i--) {
    const start = now - (i + 1) * 60000, end = now - i * 60000;
    labels.push(new Date(end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    const inMin = attempts.filter(a => a.ts > start && a.ts <= end);
    failed.push(inMin.filter(a => a.status === 'failed').length);
    ok.push(inMin.filter(a => a.status === 'success').length);
    blocked.push(inMin.filter(a => ['blocked', 'locked', 'success_denied'].includes(a.status)).length);
  }
  if (typeof Chart === 'undefined') return;
  const data = { labels, datasets: [
    { label: 'Failed', data: failed, backgroundColor: '#ef4444' },
    { label: 'Success', data: ok, backgroundColor: '#22c55e' },
    { label: 'Blocked / locked', data: blocked, backgroundColor: '#f59e0b' },
  ] };
  if (!chart) {
    chart = new Chart($('chart'), { type: 'bar', data, options: {
      animation: false, maintainAspectRatio: false,
      scales: { x: { stacked: true, ticks: { color: '#8b98a5', maxTicksLimit: 10 }, grid: { display: false } },
                y: { stacked: true, beginAtZero: true, ticks: { color: '#8b98a5', precision: 0 }, grid: { color: '#263240' } } },
      plugins: { legend: { labels: { color: '#e6edf3' } } } } });
  } else { chart.data = data; chart.update(); }
}

// ---------- recovery panel ----------
let planTimer = null;
function loadPlan() {
  clearTimeout(planTimer);
  planTimer = setTimeout(async () => {
    const p = await api('GET', '/api/restore/plan');
    const row = (k, v) => el('div', {}, el('b', {}, k), v);
    $('plan').replaceChildren(
      row('Attack started', p.attack_started ? fmtDate(Date.parse(p.attack_started)) : 'no open attack alerts'),
      row('Known-good backup', p.chosen ? `${fmtDate(p.chosen.created_ms)} (${p.chosen.records} records)` : 'NONE'),
      row('Skipped', p.skipped && p.skipped.length ? `${p.skipped.length} backup(s) taken after the attack` : '-'),
      el('div', { class: 'muted' }, p.why));
    $('btnRestore').disabled = !p.chosen;
  }, 200);
}
async function refreshVerify() {
  const list = await api('GET', '/api/backups/verify');
  verify = Object.fromEntries(list.map(v => [v.file, v]));
  if (state) renderBackups(state.backups);
}

$('btnRestore').addEventListener('click', async () => {
  $('btnRestore').disabled = true;
  $('steps').replaceChildren(); $('restoreResult').textContent = 'Restoring...'; $('restoreResult').className = 'result';
  try {
    const r = await api('POST', '/api/restore', {});
    showSteps(r.steps);
    $('restoreResult').textContent = `Recovered ${r.records} records in ${(r.duration_ms / 1000).toFixed(2)} s (RTO ${r.rto_ms / 60000} min ${r.within_rto ? 'met' : 'MISSED'})`;
    $('restoreResult').className = 'result ' + (r.within_rto ? 'ok' : 'err');
  } catch (e) {
    showSteps((e.data && e.data.steps) || []);
    $('restoreResult').textContent = 'Restore failed: ' + e.message; $('restoreResult').className = 'result err';
  }
  $('btnRestore').disabled = false;
  refreshVerify();
});
function showSteps(steps) {
  $('steps').replaceChildren(...steps.map(s => el('li', { class: s.ok ? 'ok' : 'warn' }, `[${s.t_ms} ms] ${s.msg}`)));
}
$('btnBackup').addEventListener('click', async () => {
  try { const m = await api('POST', '/api/backup'); toast(`Backup ${m.file} (${m.records} records)`, false); refreshVerify(); }
  catch (e) { toast(e.message, true); }
});
$('btnMode').addEventListener('click', () => api('POST', '/api/mode', { mode: state && state.mode === 'on' ? 'off' : 'on' }));
$('btnAckAll').addEventListener('click', () => api('POST', '/api/alerts/ack', { id: 'all' }));

// ---------- live updates + critical alert sound ----------
let toastTimer;
function toast(text, bad = true) {
  $('toast').textContent = text; $('toast').classList.remove('hidden');
  $('toast').style.background = bad ? '' : '#15803d';
  clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').classList.add('hidden'), 6000);
}
function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [0, 0.25, 0.5].forEach(t => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.frequency.value = 880; o.connect(g); g.connect(ctx.destination);
      g.gain.setValueAtTime(0.15, ctx.currentTime + t); g.gain.setValueAtTime(0, ctx.currentTime + t + 0.15);
      o.start(ctx.currentTime + t); o.stop(ctx.currentTime + t + 0.16);
    });
  } catch {}
}

const socket = io();
socket.on('update', render);
socket.on('alert', a => {
  if (a.severity === 'Critical') { beep(); toast(`CRITICAL ${a.rule}: ${a.message}`); }
  else if (a.severity === 'High') toast(`${a.rule}: ${a.message}`);
});
refreshVerify();
setInterval(refreshVerify, 30000);
