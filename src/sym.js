const crypto = require('crypto');
const fs = require('fs');
const { Transform, pipeline } = require('stream');
const { promisify } = require('util');
const { wipe, u32be, constantTimeEquals } = require('./util');

const pipelineAsync = promisify(pipeline);

const MAGIC_SCF1 = Buffer.from('SCF1', 'ascii');
const MAGIC_SKF1 = Buffer.from('SKF1', 'ascii');
const HMAC_LEN = 32;
const SALT_LEN = 16;
const PBKDF2_ITERS = 200_000;

function algId(alg) {
  if (alg === 'AES') return 1;
  if (alg === '3DES' || alg === 'DES3' || alg === 'DESede') return 2;
  throw new Error('Unsupported algorithm: ' + alg);
}

function algFromId(id) {
  if (id === 1) return 'AES';
  if (id === 2) return '3DES';
  throw new Error('Unknown alg id: ' + id);
}

function modeId(mode) {
  if (mode === 'CBC') return 1;
  if (mode === 'CFB') return 2;
  if (mode === 'OFB') return 3;
  throw new Error('Unsupported mode: ' + mode);
}

function modeFromId(id) {
  if (id === 1) return 'CBC';
  if (id === 2) return 'CFB';
  if (id === 3) return 'OFB';
  throw new Error('Unknown mode id: ' + id);
}

function blockSize(alg) {
  return alg === 'AES' ? 16 : 8;
}

function encKeyLen(alg) {
  return alg === 'AES' ? 32 : 24;
}

function cipherName(alg, mode) {
  if (alg === 'AES') return `aes-256-${mode.toLowerCase()}`;
  if (alg === '3DES') return `des-ede3-${mode.toLowerCase()}`;
  throw new Error('Unsupported algorithm: ' + alg);
}

function deriveKeysFromPassword(password, salt, iters, alg) {
  const outLen = encKeyLen(alg) + 32;
  const km = crypto.pbkdf2Sync(password, salt, iters, outLen, 'sha256');
  const kEnc = km.subarray(0, encKeyLen(alg));
  const kMac = km.subarray(encKeyLen(alg));
  return { kEnc: Buffer.from(kEnc), kMac: Buffer.from(kMac) };
}

function headerBuffer({ version, alg, mode, iters, salt, iv }) {
  const parts = [
    MAGIC_SCF1,
    Buffer.from([version & 0xff, algId(alg) & 0xff, modeId(mode) & 0xff]),
    u32be(iters >>> 0),
    Buffer.from([salt.length & 0xff]),
    salt,
    Buffer.from([iv.length & 0xff]),
    iv,
  ];
  return Buffer.concat(parts);
}

function parseHeader(buf) {
  let off = 0;
  const magic = buf.subarray(off, off + 4);
  off += 4;
  if (!magic.equals(MAGIC_SCF1)) throw new Error('Bad magic');
  const version = buf.readUInt8(off++);
  if (version !== 1) throw new Error('Unsupported version: ' + version);
  const alg = algFromId(buf.readUInt8(off++));
  const mode = modeFromId(buf.readUInt8(off++));
  const iters = buf.readUInt32BE(off);
  off += 4;
  const saltLen = buf.readUInt8(off++);
  const salt = buf.subarray(off, off + saltLen);
  off += saltLen;
  const ivLen = buf.readUInt8(off++);
  const iv = buf.subarray(off, off + ivLen);
  off += ivLen;
  return { headerLen: off, version, alg, mode, iters, salt: Buffer.from(salt), iv: Buffer.from(iv) };
}

class HmacTap extends Transform {
  constructor(hmac) {
    super();
    this.hmac = hmac;
  }
  _transform(chunk, enc, cb) {
    try {
      this.hmac.update(chunk);
      cb(null, chunk);
    } catch (e) {
      cb(e);
    }
  }
}

function keyfileWrite(outPath, rawKey, macKey, dataAlg, dataMode, keyPass) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(16);
  const iters = PBKDF2_ITERS;

  const { kEnc, kMac } = deriveKeysFromPassword(keyPass, salt, iters, 'AES');
  try {
    const payload = Buffer.concat([u32be(rawKey.length), rawKey, u32be(macKey.length), macKey]);

    const c = crypto.createCipheriv('aes-256-cbc', kEnc, iv);
    const ct = Buffer.concat([c.update(payload), c.final()]);
    wipe(payload);

    const mac = crypto.createHmac('sha256', kMac);
    mac.update(Buffer.from('KEYFILE', 'ascii'));
    mac.update(Buffer.from([1, algId(dataAlg), modeId(dataMode)]));
    mac.update(u32be(iters));
    mac.update(salt);
    mac.update(iv);
    mac.update(ct);
    const tag = mac.digest();

    const out = Buffer.concat([
      MAGIC_SKF1,
      Buffer.from([1, algId(dataAlg), modeId(dataMode)]),
      u32be(iters),
      Buffer.from([salt.length]),
      salt,
      Buffer.from([iv.length]),
      iv,
      u32be(ct.length),
      ct,
      tag,
    ]);

    fs.writeFileSync(outPath, out);
    wipe(ct);
  } finally {
    wipe(kEnc);
    wipe(kMac);
  }
}

function keyfileRead(inPath, keyPass) {
  const b = fs.readFileSync(inPath);
  let off = 0;
  if (!b.subarray(0, 4).equals(MAGIC_SKF1)) throw new Error('Bad keyfile magic');
  off += 4;
  const version = b.readUInt8(off++);
  if (version !== 1) throw new Error('Unsupported keyfile version: ' + version);
  const dataAlg = algFromId(b.readUInt8(off++));
  const dataMode = modeFromId(b.readUInt8(off++));
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

  const { kEnc, kMac } = deriveKeysFromPassword(keyPass, salt, iters, 'AES');
  try {
    const mac = crypto.createHmac('sha256', kMac);
    mac.update(Buffer.from('KEYFILE', 'ascii'));
    mac.update(Buffer.from([version, algId(dataAlg), modeId(dataMode)]));
    mac.update(u32be(iters));
    mac.update(salt);
    mac.update(iv);
    mac.update(ct);
    const expected = mac.digest();
    if (!constantTimeEquals(expected, tag)) throw new Error('Keyfile MAC verification failed');

    const d = crypto.createDecipheriv('aes-256-cbc', kEnc, iv);
    const payload = Buffer.concat([d.update(ct), d.final()]);
    let pOff = 0;
    const rawLen = payload.readUInt32BE(pOff);
    pOff += 4;
    const rawKey = Buffer.from(payload.subarray(pOff, pOff + rawLen));
    pOff += rawLen;
    const macLen = payload.readUInt32BE(pOff);
    pOff += 4;
    const macKey = Buffer.from(payload.subarray(pOff, pOff + macLen));
    wipe(payload);

    return { rawKey, macKey, alg: dataAlg, mode: dataMode };
  } finally {
    wipe(kEnc);
    wipe(kMac);
  }
}

async function encryptWithPassword(inPath, outPath, password, alg, mode) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(blockSize(alg));
  const iters = PBKDF2_ITERS;

  const { kEnc, kMac } = deriveKeysFromPassword(password, salt, iters, alg);
  try {
    const header = headerBuffer({ version: 1, alg, mode, iters, salt, iv });

    const mac = crypto.createHmac('sha256', kMac);
    mac.update(header);

    const cipher = crypto.createCipheriv(cipherName(alg, mode), kEnc, iv);

    const out = fs.createWriteStream(outPath);
    out.write(header);

    await pipelineAsync(
      fs.createReadStream(inPath),
      cipher,
      new HmacTap(mac),
      out
    );

    fs.appendFileSync(outPath, mac.digest());
  } finally {
    wipe(kEnc);
    wipe(kMac);
  }
}

async function decryptWithPassword(inPath, outPath, password) {
  const st = fs.statSync(inPath);
  if (st.size < 16) throw new Error('Cipher file too small');

  const fd = fs.openSync(inPath, 'r');
  try {
    const headBuf = Buffer.alloc(Math.min(st.size, 4096));
    const got = fs.readSync(fd, headBuf, 0, headBuf.length, 0);
    const { headerLen, alg, mode, iters, salt, iv } = parseHeader(headBuf.subarray(0, got));

    const ctLen = st.size - headerLen - HMAC_LEN;
    if (ctLen < 0) throw new Error('Bad ciphertext length');

    const { kEnc, kMac } = deriveKeysFromPassword(password, salt, iters, alg);
    try {
      const header = headerBuffer({ version: 1, alg, mode, iters, salt, iv });
      const mac = crypto.createHmac('sha256', kMac);
      mac.update(header);

      const cipher = crypto.createDecipheriv(cipherName(alg, mode), kEnc, iv);

      await pipelineAsync(
        fs.createReadStream(inPath, { start: headerLen, end: headerLen + ctLen - 1 }),
        new HmacTap(mac),
        cipher,
        fs.createWriteStream(outPath)
      );

      const tag = Buffer.alloc(HMAC_LEN);
      fs.readSync(fd, tag, 0, HMAC_LEN, st.size - HMAC_LEN);
      const expected = mac.digest();
      if (!constantTimeEquals(expected, tag)) throw new Error('MAC verification failed');
    } finally {
      wipe(kEnc);
      wipe(kMac);
    }
  } finally {
    fs.closeSync(fd);
  }
}

async function encryptWithGeneratedKey(inPath, outPath, keyOutPath, keyPass, alg, mode) {
  const rawKey = crypto.randomBytes(encKeyLen(alg));
  const macKey = crypto.randomBytes(32);
  try {
    const salt = Buffer.alloc(0);
    const iv = crypto.randomBytes(blockSize(alg));
    const iters = 0;

    const header = headerBuffer({ version: 1, alg, mode, iters, salt, iv });

    const mac = crypto.createHmac('sha256', macKey);
    mac.update(header);

    const cipher = crypto.createCipheriv(cipherName(alg, mode), rawKey, iv);

    const out = fs.createWriteStream(outPath);
    out.write(header);

    await pipelineAsync(
      fs.createReadStream(inPath),
      cipher,
      new HmacTap(mac),
      out
    );

    fs.appendFileSync(outPath, mac.digest());

    keyfileWrite(keyOutPath, rawKey, macKey, alg, mode, keyPass);
  } finally {
    wipe(rawKey);
    wipe(macKey);
  }
}

async function decryptWithKeyfile(inPath, outPath, keyfilePath, keyPass) {
  const dk = keyfileRead(keyfilePath, keyPass);
  try {
    const st = fs.statSync(inPath);
    const fd = fs.openSync(inPath, 'r');
    try {
      const headBuf = Buffer.alloc(Math.min(st.size, 4096));
      const got = fs.readSync(fd, headBuf, 0, headBuf.length, 0);
      const { headerLen, alg, mode, iters, salt, iv } = parseHeader(headBuf.subarray(0, got));

      if (alg !== dk.alg || mode !== dk.mode) throw new Error('Algorithm/mode mismatch');
      if (iters !== 0 || salt.length !== 0) throw new Error('Expected raw-key encrypted file');

      const ctLen = st.size - headerLen - HMAC_LEN;
      if (ctLen < 0) throw new Error('Bad ciphertext length');

      const header = headerBuffer({ version: 1, alg, mode, iters, salt, iv });
      const mac = crypto.createHmac('sha256', dk.macKey);
      mac.update(header);

      const decipher = crypto.createDecipheriv(cipherName(alg, mode), dk.rawKey, iv);

      await pipelineAsync(
        fs.createReadStream(inPath, { start: headerLen, end: headerLen + ctLen - 1 }),
        new HmacTap(mac),
        decipher,
        fs.createWriteStream(outPath)
      );

      const tag = Buffer.alloc(HMAC_LEN);
      fs.readSync(fd, tag, 0, HMAC_LEN, st.size - HMAC_LEN);
      const expected = mac.digest();
      if (!constantTimeEquals(expected, tag)) throw new Error('MAC verification failed');
    } finally {
      fs.closeSync(fd);
    }
  } finally {
    wipe(dk.rawKey);
    wipe(dk.macKey);
  }
}

async function symEncrypt(m) {
  const alg = m.req('--alg');
  const mode = m.req('--mode');
  const inPath = m.req('--in');
  const outPath = m.req('--out');
  const genKey = m.has('--genkey');
  const pass = m.opt('--pass');

  if (genKey && pass != null) throw new Error('For --genkey do not use --pass; use --keypass');
  if (!genKey && pass == null) throw new Error('Specify --pass or --genkey');

  if (genKey) {
    const keyOut = m.req('--keyout');
    const keyPass = m.req('--keypass');
    await encryptWithGeneratedKey(inPath, outPath, keyOut, keyPass, alg, mode);
    return;
  }

  await encryptWithPassword(inPath, outPath, pass, alg, mode);
}

async function symDecrypt(m) {
  const inPath = m.req('--in');
  const outPath = m.req('--out');
  const pass = m.req('--pass');
  const keyfile = m.opt('--keyfile');

  if (keyfile) {
    await decryptWithKeyfile(inPath, outPath, keyfile, pass);
    return;
  }

  await decryptWithPassword(inPath, outPath, pass);
}

module.exports = { symEncrypt, symDecrypt };
