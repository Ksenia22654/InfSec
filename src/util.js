const crypto = require('crypto');

function wipe(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0);
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function constantTimeEquals(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { wipe, u32be, constantTimeEquals };
