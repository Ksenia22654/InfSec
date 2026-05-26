const crypto = require('crypto');
const fs = require('fs');
const { wipe, u32be, constantTimeEquals } = require('./util');

const MAGIC_RKF1 = Buffer.from('RKF1', 'ascii');
const HMAC_LEN = 32;
const SALT_LEN = 16;
const PBKDF2_ITERS = 200_000;

function deriveKeys(password, salt, iters) {
  const km = crypto.pbkdf2Sync(password, salt, iters, 64, 'sha256');
  const kEnc = Buffer.from(km.subarray(0, 32));
  const kMac = Buffer.from(km.subarray(32, 64));
  wipe(km);
  return { kEnc, kMac };
}

function saveEncryptedKeypair(outFile, privPem, pubPem, password) {
  const privB = Buffer.from(privPem, 'utf8');
  const pubB = Buffer.from(pubPem, 'utf8');
  const payload = Buffer.concat([u32be(privB.length), privB, u32be(pubB.length), pubB]);

  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(16);
  const iters = PBKDF2_ITERS;

  const { kEnc, kMac } = deriveKeys(password, salt, iters);
  try {
    const c = crypto.createCipheriv('aes-256-cbc', kEnc, iv);
    const ct = Buffer.concat([c.update(payload), c.final()]);
    wipe(payload);

    const mac = crypto.createHmac('sha256', kMac);
    mac.update(Buffer.from('RSAKEYPAIR', 'ascii'));
    mac.update(Buffer.from([1]));
    mac.update(u32be(iters));
    mac.update(salt);
    mac.update(iv);
    mac.update(ct);
    const tag = mac.digest();

    const out = Buffer.concat([
      MAGIC_RKF1,
      Buffer.from([1]),
      u32be(iters),
      Buffer.from([salt.length]),
      salt,
      Buffer.from([iv.length]),
      iv,
      u32be(ct.length),
      ct,
      tag,
    ]);
    fs.writeFileSync(outFile, out);
    wipe(ct);
  } finally {
    wipe(kEnc);
    wipe(kMac);
  }
}

function loadEncryptedKeypair(inFile, password) {
  const b = fs.readFileSync(inFile);
  let off = 0;
  if (!b.subarray(0, 4).equals(MAGIC_RKF1)) throw new Error('Bad keypair magic');
  off += 4;
  const version = b.readUInt8(off++);
  if (version !== 1) throw new Error('Unsupported keypair version: ' + version);
  const iters = b.readUInt32BE(off);
  off += 4;
  const saltLen = b.readUInt8(off++);
  const salt = b.subarray(off, off + saltLen);
  off += saltLen;
  const ivLen = b.readUInt8(off++);
  const iv = b.subarray(off, off + ivLen);
  off += ivLen;
  const ctLen = b.readUInt32BE(off);
  off += 4;
  const ct = b.subarray(off, off + ctLen);
  off += ctLen;
  const tag = b.subarray(off, off + HMAC_LEN);

  const { kEnc, kMac } = deriveKeys(password, salt, iters);
  try {
    const mac = crypto.createHmac('sha256', kMac);
    mac.update(Buffer.from('RSAKEYPAIR', 'ascii'));
    mac.update(Buffer.from([version]));
    mac.update(u32be(iters));
    mac.update(salt);
    mac.update(iv);
    mac.update(ct);
    const expected = mac.digest();
    if (!constantTimeEquals(expected, tag)) throw new Error('Keypair MAC verification failed');

    const d = crypto.createDecipheriv('aes-256-cbc', kEnc, iv);
    const payload = Buffer.concat([d.update(ct), d.final()]);

    let pOff = 0;
    const privLen = payload.readUInt32BE(pOff);
    pOff += 4;
    const privPem = payload.subarray(pOff, pOff + privLen).toString('utf8');
    pOff += privLen;
    const pubLen = payload.readUInt32BE(pOff);
    pOff += 4;
    const pubPem = payload.subarray(pOff, pOff + pubLen).toString('utf8');
    wipe(payload);

    return { privPem, pubPem };
  } finally {
    wipe(kEnc);
    wipe(kMac);
  }
}

async function rsaGen(m) {
  const bits = parseInt(m.req('--bits'), 10);
  const outPublic = m.req('--out-public');
  const outKeypair = m.req('--out-keypair');
  const pass = m.req('--pass');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(outPublic, publicKey, 'utf8');
  saveEncryptedKeypair(outKeypair, privateKey, publicKey, pass);
}

async function rsaExportPublic(m) {
  const inKeypair = m.req('--in-keypair');
  const pass = m.req('--pass');
  const outPublic = m.req('--out-public');

  const { pubPem } = loadEncryptedKeypair(inKeypair, pass);
  fs.writeFileSync(outPublic, pubPem, 'utf8');
}

async function rsaSaveKeypair(m) {
  const inPriv = m.req('--in-private');
  const inPub = m.req('--in-public');
  const outKeypair = m.req('--out-keypair');
  const pass = m.req('--pass');

  const privPem = fs.readFileSync(inPriv, 'utf8');
  const pubPem = fs.readFileSync(inPub, 'utf8');
  saveEncryptedKeypair(outKeypair, privPem, pubPem, pass);
}

async function rsaLoadKeypair(m) {
  const inKeypair = m.req('--in-keypair');
  const pass = m.req('--pass');
  const outPriv = m.req('--out-private');
  const outPub = m.req('--out-public');

  const { privPem, pubPem } = loadEncryptedKeypair(inKeypair, pass);
  fs.writeFileSync(outPriv, privPem, 'utf8');
  fs.writeFileSync(outPub, pubPem, 'utf8');
}

module.exports = {
  rsaGen,
  rsaExportPublic,
  rsaSaveKeypair,
  rsaLoadKeypair,
  loadEncryptedKeypair,
};
