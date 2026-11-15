'use strict';
const form = document.getElementById('loginForm');
const msg = document.getElementById('msg');

function show(text, cls) { msg.textContent = text; msg.className = 'msg ' + cls; }

form.addEventListener('submit', async e => {
  e.preventDefault();
  show('', '');
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
      }),
    });
    const data = await res.json();
    if (data.status === 'success') { show('Signed in - redirecting...', 'ok'); location.href = data.redirect; }
    else if (data.status === 'blocked') show(`Too many failed attempts. Try again in ${data.retry_after_s} s.`, 'warn');
    else if (data.status === 'locked') show(data.message, 'err');
    else show('Invalid username or password.', 'err');      // same message either way: no username enumeration
  } catch {
    show('Server unreachable.', 'err');
  }
  document.getElementById('password').value = '';
});
