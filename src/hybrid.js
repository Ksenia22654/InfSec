const crypto = require('crypto');
const fs = require('fs');
const { Transform, pipeline } = require('stream');
const { promisify } = require('util');
const { wipe, u32be, constantTimeEquals } = require('./util');
const { loadEncryptedKeypair } = require('./rsa');

const pipelineAsync = promisify(pipeline);

const MAGIC_HCF1 = Buffer.from('HCF1', 'ascii');
const HMAC_LEN = 32;

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

async function hybEncrypt(m) {
  const inPath = m.req('--in');
  const outPath = m.req('--out');
  const pubPath = m.req('--to-public');

  const pubPem = fs.readFileSync(pubPath, 'utf8');

  const aesKey = crypto.randomBytes(32);
  const macKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const keyPayload = Buffer.concat([aesKey, macKey]);
  let wrapped;
  try {
    wrapped = crypto.publicEncrypt(
      {
        key: pubPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      keyPayload
    );
  } finally {
    wipe(keyPayload);
  }

  const header = Buffer.concat([
    MAGIC_HCF1,
    Buffer.from([1]),
    u32be(wrapped.length),
    wrapped,
    Buffer.from([iv.length]),
    iv,
  ]);

  const mac = crypto.createHmac('sha256', macKey);
  mac.update(Buffer.from('HYBRID', 'ascii'));
  mac.update(Buffer.from([1]));
  mac.update(u32be(wrapped.length));
  mac.update(wrapped);
  mac.update(Buffer.from([iv.length]));
  mac.update(iv);

  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);

  try {
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
    wipe(aesKey);
    wipe(macKey);
    wipe(iv);
    wipe(wrapped);
  }
}

async function hybDecrypt(m) {
  const inPath = m.req('--in');
  const outPath = m.req('--out');
  const keypairFile = m.req('--keypair');
  const pass = m.req('--pass');

  const { privPem } = loadEncryptedKeypair(keypairFile, pass);

  const st = fs.statSync(inPath);
  if (st.size < 4 + 1 + 4 + 1 + 16 + HMAC_LEN) throw new Error('Cipher file too small');

  const fd = fs.openSync(inPath, 'r');
  try {
    const pre = Buffer.alloc(Math.min(st.size, 8192));
    const got = fs.readSync(fd, pre, 0, pre.length, 0);

    let off = 0;
    if (!pre.subarray(0, 4).equals(MAGIC_HCF1)) throw new Error('Bad hybrid magic');
    off += 4;
    const version = pre.readUInt8(off++);
    if (version !== 1) throw new Error('Unsupported hybrid version: ' + version);
    const wrappedLen = pre.readUInt32BE(off);
    off += 4;

    const need = 4 + 1 + 4 + wrappedLen + 1;
    if (got < need) throw new Error('Header too large for buffer');

    const wrapped = Buffer.from(pre.subarray(off, off + wrappedLen));
    off += wrappedLen;
    const ivLen = pre.readUInt8(off++);
    const iv = Buffer.from(pre.subarray(off, off + ivLen));
    off += ivLen;

    const headerLen = off;
    const ctLen = st.size - headerLen - HMAC_LEN;
    if (ctLen < 0) throw new Error('Bad ciphertext length');

    const keyPayload = crypto.privateDecrypt(
      {
        key: privPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      wrapped
    );
    if (keyPayload.length !== 64) throw new Error('Bad wrapped key payload');
    const aesKey = Buffer.from(keyPayload.subarray(0, 32));
    const macKey = Buffer.from(keyPayload.subarray(32, 64));
    wipe(keyPayload);

    const mac = crypto.createHmac('sha256', macKey);
    mac.update(Buffer.from('HYBRID', 'ascii'));
    mac.update(Buffer.from([version]));
    mac.update(u32be(wrapped.length));
    mac.update(wrapped);
    mac.update(Buffer.from([iv.length]));
    mac.update(iv);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);

    try {
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
      wipe(aesKey);
      wipe(macKey);
      wipe(wrapped);
      wipe(iv);
    }
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { hybEncrypt, hybDecrypt };
