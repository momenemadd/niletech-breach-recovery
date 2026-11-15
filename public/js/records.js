'use strict';
const rowsEl = document.getElementById('rows');
const msg = document.getElementById('msg');

async function load() {
  try {
    const rows = await api('GET', '/api/records');
    msg.textContent = '';
    document.getElementById('count').textContent = `${rows.length} records`;
    rowsEl.replaceChildren(...rows.map(r => el('tr', {},
      el('td', {}, r.id), el('td', {}, r.full_name), el('td', {}, r.national_id), el('td', {}, r.department),
      el('td', { class: 'num' }, r.salary.toLocaleString()), el('td', {}, r.phone), el('td', {}, r.email),
      el('td', {}, el('button', { class: 'small danger', onclick: () => del(r.id) }, 'Delete')))));
  } catch (e) {
    msg.textContent = e.message; msg.className = 'msg warn';
  }
}
async function del(id) {
  await api('DELETE', `/api/records/${id}`);
  load();
}
load();
