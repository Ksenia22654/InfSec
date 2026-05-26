import { readFile } from 'fs/promises';

const INTERVAL_MS = 10_000;
const WINDOW_MS = 60_000;
const THRESHOLD = 5;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function safeJsonParse(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

async function analyzeOnce() {
  let text = '';
  try {
    text = await readFile('access.log', 'utf8');
  } catch {
    return;
  }

  const now = Date.now();
  const counts = new Map();

  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const rec = safeJsonParse(line);
    if (!rec || !rec.time || !rec.ip) continue;
    const t = Date.parse(rec.time);
    if (!Number.isFinite(t)) continue;
    if (now - t > WINDOW_MS) continue;
    if (rec.ok === true) continue;
    counts.set(rec.ip, (counts.get(rec.ip) || 0) + 1);
  }

  for (const [ip, n] of counts.entries()) {
    if (n > THRESHOLD) {
      console.log(`[ALERT] IP ${ip} failed=${n} in_last_minute`);
    }
  }
}

async function main() {
  while (true) {
    await analyzeOnce();
    await sleep(INTERVAL_MS);
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
