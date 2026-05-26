import crypto from 'crypto';
import { readFile } from 'fs/promises';
import readline from 'readline/promises';

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

async function getHashString() {
  const arg = process.argv[2];
  if (arg) return arg.trim();
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const s = await rl.question('Enter hash (salt:hash): ');
  rl.close();
  return (s || '').trim();
}

async function main() {
  const hashStr = await getHashString();
  const [saltHex, hashHex] = hashStr.split(':');
  if (!saltHex || !hashHex) {
    console.error('Invalid format. Expected salt:hash');
    process.exitCode = 1;
    return;
  }

  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');

  const dictText = await readFile('dictionary.txt', 'utf8');
  const words = dictText
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  const t0 = process.hrtime.bigint();

  for (const password of words) {
    const dk = await scryptAsync(password, salt);
    if (dk.length === expected.length && crypto.timingSafeEqual(dk, expected)) {
      const t1 = process.hrtime.bigint();
      const ms = Number(t1 - t0) / 1e6;
      console.log(`FOUND password="${password}" timeMs=${ms.toFixed(2)}`);
      return;
    }
  }

  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`NOT FOUND timeMs=${ms.toFixed(2)}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
