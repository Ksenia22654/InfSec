#!/usr/bin/env node

const path = require('path');
const { symEncrypt, symDecrypt } = require('./sym');
const { rsaGen, rsaExportPublic, rsaSaveKeypair, rsaLoadKeypair } = require('./rsa');
const { hybEncrypt, hybDecrypt } = require('./hybrid');

function usage() {
  console.log(
    'crypto-js-cli\n\n' +
      'Commands:\n' +
      '  sym-encrypt --alg AES|3DES --mode CBC|CFB|OFB --in <plain> --out <cipher> (--pass <password> | --genkey --keyout <encKeyFile> --keypass <password>)\n' +
      '  sym-decrypt --in <cipher> --out <plain> (--keyfile <encKeyFile> --pass <password> | --pass <password>)\n\n' +
      '  rsa-gen --bits 2048|3072|4096 --out-public <pub.pem> --out-keypair <pair.enc> --pass <password>\n' +
      '  rsa-export-public --in-keypair <pair.enc> --pass <password> --out-public <pub.pem>\n' +
      '  rsa-save-keypair --in-private <priv.pem> --in-public <pub.pem> --out-keypair <pair.enc> --pass <password>\n' +
      '  rsa-load-keypair --in-keypair <pair.enc> --pass <password> --out-private <priv.pem> --out-public <pub.pem>\n\n' +
      '  hyb-encrypt --in <plain> --out <cipher> --to-public <pub.pem>\n' +
      '  hyb-decrypt --in <cipher> --out <plain> --keypair <pair.enc> --pass <password>\n'
  );
}

function parseArgs(argv) {
  const m = new Map();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) throw new Error('Expected option starting with --, got: ' + a);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      m.set(a, next);
      i++;
    } else {
      m.set(a, 'true');
    }
  }
  return {
    has: (k) => m.has(k),
    req: (k) => {
      if (!m.has(k)) throw new Error('Missing required option: ' + k);
      const v = m.get(k);
      return v === 'true' ? 'true' : v;
    },
    opt: (k) => {
      if (!m.has(k)) return null;
      const v = m.get(k);
      return v === 'true' ? null : v;
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === 'help') {
    usage();
    return;
  }

  const cmd = args[0];
  const m = parseArgs(args.slice(1));

  switch (cmd) {
    case 'sym-encrypt':
      await symEncrypt(m);
      return;
    case 'sym-decrypt':
      await symDecrypt(m);
      return;
    case 'rsa-gen':
      await rsaGen(m);
      return;
    case 'rsa-export-public':
      await rsaExportPublic(m);
      return;
    case 'rsa-save-keypair':
      await rsaSaveKeypair(m);
      return;
    case 'rsa-load-keypair':
      await rsaLoadKeypair(m);
      return;
    case 'hyb-encrypt':
      await hybEncrypt(m);
      return;
    case 'hyb-decrypt':
      await hybDecrypt(m);
      return;
    default:
      throw new Error('Unknown command: ' + cmd);
  }
}

main().catch((e) => {
  console.error('Error:', e && e.message ? e.message : e);
  process.exit(1);
});
