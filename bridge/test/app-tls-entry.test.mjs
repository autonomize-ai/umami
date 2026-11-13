// scripts/tls-server.cjs is the Umami APP's container entry (AUTPE-8197, part
// F2); it lives with the bridge tests because this is the repo's node:test run.
// It runs as shipped, beside a stub server.js that creates its listener with one
// http.createServer call, as Next's standalone start-server does. The stub also
// records the options passed to https.createServer so the TLS 1.2 pin is asserted
// directly (Node's default floor is already 1.2, so a handshake cannot see it go).
// The TLS case needs the openssl binary and skips without it.
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const ENTRY = new URL('../../scripts/tls-server.cjs', import.meta.url).pathname;
const NAME = 'genesis-umami.test.svc';

let haveOpenssl = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  haveOpenssl = false;
}
const skipTls = haveOpenssl ? false : 'openssl not installed';

const STUB = `
const https = require('node:https');
const real = https.createServer;
https.createServer = (o, l) => {
  console.log('OPTS ' + JSON.stringify({ minVersion: o.minVersion }));
  return real(o, l);
};
require('node:http')
  .createServer((req, res) => res.end('ok'))
  .listen(Number(process.env.PORT), '127.0.0.1', () => console.log('READY'));
`;

// Same layout as the image: <root>/server.js and <root>/scripts/tls-server.cjs.
function workdir() {
  const dir = mkdtempSync(join(tmpdir(), 'umami-tls-'));
  mkdirSync(join(dir, 'scripts'));
  copyFileSync(ENTRY, join(dir, 'scripts', 'tls-server.cjs'));
  writeFileSync(join(dir, 'server.js'), STUB);
  return dir;
}

function pki(dir) {
  const run = (...a) => execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=test ca', '-days', '2');
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'o.key', '-out', 'other.crt', '-subj', '/CN=other ca', '-days', '2');
  run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tls.key', '-out', 'l.csr', '-subj', '/CN=umami');
  writeFileSync(join(dir, 'ext'), `subjectAltName=DNS:${NAME},DNS:localhost\n`);
  run('x509', '-req', '-in', 'l.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tls.crt', '-days', '2', '-extfile', 'ext');
}

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function start(dir, env) {
  const port = await freePort();
  const child = spawn('node', ['scripts/tls-server.cjs'], { cwd: dir, env: { PATH: process.env.PATH, PORT: String(port), ...env } });
  let out = '';
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => {
      out += d;
      if (out.includes('READY')) resolve();
    });
    child.on('exit', (code) => reject(new Error(`exited ${code} before READY: ${out}`)));
    setTimeout(() => reject(new Error(`timeout: ${out}`)), 8000);
  });
  return { child, port, out };
}

function get(port, options) {
  return new Promise((resolve, reject) => {
    https
      .get({ host: '127.0.0.1', port, path: '/', ...options }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      })
      .on('error', reject);
  });
}

test('TLS unset: pass-through, plain http', async () => {
  const dir = workdir();
  const { child, port, out } = await start(dir, {});
  try {
    assert.ok(!out.includes('OPTS'), 'no https listener when TLS is off');
    const status = await new Promise((r) => http.get({ host: '127.0.0.1', port }, (res) => { res.resume(); r(res.statusCode); }));
    assert.equal(status, 200);
  } finally {
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('half-set pair or unreadable files: exit 1 with the message, never plain http', async () => {
  const dir = workdir();
  try {
    // A free port, so a fallback to plain http would serve and hit the timeout
    // (status null) rather than fail for an unrelated bind error.
    const port = String(await freePort());
    for (const [env, message] of [
      [{ GENESIS_TLS_CERT: '/x' }, /must both be set/],
      [{ GENESIS_TLS_KEY: '/y' }, /must both be set/],
      [{ GENESIS_TLS_CERT: '/nope/c', GENESIS_TLS_KEY: '/nope/k' }, /Cannot read TLS material: ENOENT/],
    ]) {
      const r = spawnSync('node', ['scripts/tls-server.cjs'], { cwd: dir, env: { PATH: process.env.PATH, PORT: port, ...env }, timeout: 5000 });
      assert.equal(r.status, 1, JSON.stringify(env));
      assert.match(String(r.stderr), message);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TLS on: pinned to 1.2, CA-verified client served, bad CA, bad name, TLS 1.1 and plain http refused', { skip: skipTls }, async () => {
  const dir = workdir();
  pki(dir);
  const env = { GENESIS_TLS_CERT: join(dir, 'tls.crt'), GENESIS_TLS_KEY: join(dir, 'tls.key') };
  const { child, port, out } = await start(dir, env);
  try {
    assert.match(out, /OPTS {"minVersion":"TLSv1\.2"}/);
    const ca = readFileSync(join(dir, 'ca.crt'));
    assert.equal(await get(port, { ca, servername: NAME }), 200);
    assert.equal(await get(port, { ca, servername: 'localhost' }), 200, 'the bridge dials localhost, so the certificate must carry it');
    await assert.rejects(get(port, { ca: readFileSync(join(dir, 'other.crt')), servername: NAME }), /unable to verify|self.signed|issuer/i);
    await assert.rejects(get(port, { ca, servername: 'other-name.svc' }), (e) => e.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
    await assert.rejects(
      get(port, { ca, servername: NAME, minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' }),
      (e) => /protocol version|no protocols|alert|wrong version/i.test(e.message),
    );
    await assert.rejects(new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port }, resolve).on('error', reject)));
  } finally {
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});
