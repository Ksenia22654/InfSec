import http from 'http';
import crypto from 'crypto';
import { appendFile } from 'fs/promises';
import { URL } from 'url';

const PORT = 3000;
const USERNAME = 'student';
const PLAIN_PASSWORD = 'superman';

const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';
const RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY || '';

function nowIso() {
  return new Date().toISOString();
}

function getIp(req) {
  const ip = req.socket.remoteAddress || '';
  return ip;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseFormUrlEncoded(body) {
  const out = {};
  for (const part of body.split('&')) {
    if (!part) continue;
    const [k, v] = part.split('=');
    const key = decodeURIComponent(k || '');
    const val = decodeURIComponent((v || '').replace(/\+/g, ' '));
    out[key] = val;
  }
  return out;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

async function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const dk = await scryptAsync(plain, salt);
  return `${salt.toString('hex')}:${dk.toString('hex')}`;
}

async function verifyPassword(plain, stored) {
  const [saltHex, hashHex] = stored.split(':');
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scryptAsync(plain, salt);
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function genCaptcha() {
  const a = 1 + crypto.randomInt(9);
  const b = 1 + crypto.randomInt(9);
  const c = 1 + crypto.randomInt(9);
  const ops = ['+', '-', '*'];
  const op1 = ops[crypto.randomInt(ops.length)];
  const op2 = ops[crypto.randomInt(ops.length)];
  const expr = `${a}${op1}${b}${op2}${c}`;
  const answer = Math.trunc(Function(`return (${expr});`)());
  return { question: expr, answer: String(answer) };
}

async function verifyRecaptcha(token, remoteip) {
  if (!RECAPTCHA_SECRET) return { ok: true, skipped: true };
  if (!token) return { ok: false, error: 'missing_token' };

  const params = new URLSearchParams();
  params.set('secret', RECAPTCHA_SECRET);
  params.set('response', token);
  if (remoteip) params.set('remoteip', remoteip);

  const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  if (!resp.ok) return { ok: false, error: `http_${resp.status}` };
  const data = await resp.json();
  if (data && data.success) return { ok: true };
  return { ok: false, error: 'invalid' };
}

const user = {
  username: USERNAME,
  passwordHash: await hashPassword(PLAIN_PASSWORD),
};

console.log(`User: ${user.username}`);
console.log(`Password hash (salt:hash): ${user.passwordHash}`);

const stateByIp = new Map();

function getState(ip) {
  if (!stateByIp.has(ip)) {
    stateByIp.set(ip, {
      fails: 0,
      lastFailAt: 0,
      captcha: null,
    });
  }
  return stateByIp.get(ip);
}

async function logAttempt({ ip, username, ok, reason }) {
  const line = JSON.stringify({ time: nowIso(), ip, username, ok, reason }) + '\n';
  await appendFile('access.log', line, 'utf8');
}

function send(res, status, contentType, body) {
  res.statusCode = status;
  res.setHeader('content-type', contentType);
  res.end(body);
}

function renderLoginPage({ captchaQuestion, needsRecaptcha }) {
  const recaptchaBlock = needsRecaptcha
    ? (RECAPTCHA_SITE_KEY
        ? `\n<script src="https://www.google.com/recaptcha/api.js" async defer></script>\n<div class="g-recaptcha" data-sitekey="${RECAPTCHA_SITE_KEY}"></div>\n<input type="hidden" name="recaptchaToken" id="recaptchaToken" value="">\n<script>\n  document.addEventListener('submit', function(e){\n    var r = (window.grecaptcha && grecaptcha.getResponse) ? grecaptcha.getResponse() : '';\n    var el = document.getElementById('recaptchaToken');\n    if (el) el.value = r;\n  }, true);\n</script>\n`
        : `\n<div>reCAPTCHA включена на сервере, но RECAPTCHA_SITE_KEY не задан. Введите token вручную:</div>\n<input name="recaptchaToken" />\n`)
    : '';

  const captchaBlock = captchaQuestion
    ? `\n<div>CAPTCHA: решите пример <b>${captchaQuestion}</b></div>\n<input name="captchaAnswer" autocomplete="off" />\n`
    : '';

  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login</title>
</head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/login">
    <div><input name="username" placeholder="username" autocomplete="username" /></div>
    <div><input type="password" name="password" placeholder="password" autocomplete="current-password" /></div>
    ${captchaBlock}
    ${recaptchaBlock}
    <div><button type="submit">Sign in</button></div>
  </form>
</body>
</html>`;
}

const server = http.createServer(async (req, res) => {
  try {
    const ip = getIp(req);
    const u = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && u.pathname === '/login') {
      const st = getState(ip);
      const captchaQuestion = st.fails >= 2 ? (st.captcha?.question || null) : null;
      const html = renderLoginPage({ captchaQuestion, needsRecaptcha: Boolean(RECAPTCHA_SECRET) });
      return send(res, 200, 'text/html; charset=utf-8', html);
    }

    if (req.method === 'POST' && u.pathname === '/login') {
      const st = getState(ip);

      if (st.fails >= 5) {
        const delayMs = Math.min((st.fails - 4) * 500, 5000);
        await sleep(delayMs);
      }

      const body = await readBody(req);
      const form = parseFormUrlEncoded(body);
      const username = (form.username || '').trim();
      const password = form.password || '';
      const captchaAnswer = (form.captchaAnswer || '').trim();
      const recaptchaToken = (form.recaptchaToken || '').trim();

      if (st.fails >= 2) {
        if (!st.captcha) st.captcha = genCaptcha();
        if (!captchaAnswer) {
          await logAttempt({ ip, username, ok: false, reason: 'captcha_required' });
          const html = renderLoginPage({ captchaQuestion: st.captcha.question, needsRecaptcha: Boolean(RECAPTCHA_SECRET) });
          return send(res, 403, 'text/html; charset=utf-8', html);
        }
        if (captchaAnswer !== st.captcha.answer) {
          st.fails += 1;
          st.lastFailAt = Date.now();
          st.captcha = genCaptcha();
          await logAttempt({ ip, username, ok: false, reason: 'captcha_wrong' });
          const html = renderLoginPage({ captchaQuestion: st.captcha.question, needsRecaptcha: Boolean(RECAPTCHA_SECRET) });
          return send(res, 403, 'text/html; charset=utf-8', html);
        }
      }

      const recaptcha = await verifyRecaptcha(recaptchaToken, ip);
      if (!recaptcha.ok) {
        st.fails += 1;
        st.lastFailAt = Date.now();
        if (st.fails >= 2 && !st.captcha) st.captcha = genCaptcha();
        await logAttempt({ ip, username, ok: false, reason: `recaptcha_${recaptcha.error}` });
        return send(res, 403, 'application/json; charset=utf-8', JSON.stringify({ ok: false, error: 'recaptcha_failed' }));
      }

      const okUser = username === user.username;
      const okPass = okUser ? await verifyPassword(password, user.passwordHash) : false;

      if (okUser && okPass) {
        st.fails = 0;
        st.lastFailAt = 0;
        st.captcha = null;
        await logAttempt({ ip, username, ok: true, reason: 'success' });
        return send(res, 200, 'application/json; charset=utf-8', JSON.stringify({ ok: true, message: 'login_success' }));
      }

      st.fails += 1;
      st.lastFailAt = Date.now();
      if (st.fails >= 2 && !st.captcha) st.captcha = genCaptcha();
      await logAttempt({ ip, username, ok: false, reason: 'invalid_credentials' });
      return send(res, 401, 'application/json; charset=utf-8', JSON.stringify({ ok: false, message: 'login_failed' }));
    }

    send(res, 404, 'text/plain; charset=utf-8', 'Not found');
  } catch (e) {
    send(res, 500, 'application/json; charset=utf-8', JSON.stringify({ ok: false, error: 'server_error' }));
  }
});

server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
