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

// STUB_KIND picks how the stub builds its listener. "create" is what Next does
// today. The others stand in for a future Next that builds its server another
// way: the entry must exit 1, not log "TLS enabled" and serve plaintext.
const STUB = `
const https = require('node:https');
const real = https.createServer;
https.createServer = (o, l) => {
  console.log('OPTS ' + JSON.stringify({ minVersion: o.minVersion }));
  return real(o, l);
};
const handler = (req, res) => res.end('ok');
const kind = process.env.STUB_KIND || 'create';
const server =
  kind === 'new-server' ? new (require('node:http').Server)(handler)
  : kind === 'http2' ? require('node:http2').createServer(handler)
  : require('node:http').createServer(handler);
server.listen(Number(process.env.PORT), '127.0.0.1', async () => {
  // STUB_OUT: outbound https to an "external" host (an unknown CA), the way the
  // app calls a managed database or another external service. STUB_FP: a
  // fingerprint of the two functions the entry may patch. STUB_CA: how many CA
  // certificates Node trusts by default.
  if (process.env.STUB_OUT === '1') {
    const get = (opts) => new Promise((resolve) => {
      require('node:https').get({ host: '127.0.0.1', port: Number(process.env.EXT_PORT), path: '/', ...opts }, (res) => {
        res.resume();
        resolve('status ' + res.statusCode);
      }).on('error', (e) => resolve('error ' + e.code));
    });
    const viaFetch = await fetch('https://127.0.0.1:' + process.env.EXT_PORT + '/').then((r) => 'status ' + r.status, (e) => 'error ' + (e.cause && e.cause.code));
    console.log('OUT ' + JSON.stringify({ unverified: await get({ rejectUnauthorized: false }), verified: await get({}), fetch: viaFetch }));
  }
  if (process.env.STUB_FP === '1') {
    const fp = require('node:crypto').createHash('sha256')
      .update(require('node:http').createServer.toString())
      .update(require('node:net').Server.prototype.listen.toString())
      .digest('hex');
    console.log('FP ' + fp);
  }
  if (process.env.STUB_CA === '1') {
    const t = require('node:tls');
    console.log('CA ' + (typeof t.getCACertificates === 'function' ? t.getCACertificates('default').length : 'unsupported'));
  }
  console.log('READY');
});
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

async function start(dir, env, script = 'scripts/tls-server.cjs') {
  const port = await freePort();
  const child = spawn('node', [script], { cwd: dir, env: { PATH: process.env.PATH, PORT: String(port), ...env } });
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

const line = (out, tag) => (out.split('\n').find((l) => l.startsWith(tag + ' ')) || '').slice(tag.length + 1);

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

test('TLS on but the server is built another way: exit 1, never plaintext', { skip: skipTls }, async () => {
  const dir = workdir();
  pki(dir);
  const env = { GENESIS_TLS_CERT: join(dir, 'tls.crt'), GENESIS_TLS_KEY: join(dir, 'tls.key') };
  try {
    const port = String(await freePort());
    for (const kind of ['new-server', 'http2']) {
      // Without the guard the stub logs READY and answers plain http, so the
      // child is still running when the timeout fires (status null).
      const r = spawnSync('node', ['scripts/tls-server.cjs'], {
        cwd: dir,
        env: { PATH: process.env.PATH, PORT: port, STUB_KIND: kind, ...env },
        timeout: 5000,
        encoding: 'utf8',
      });
      assert.equal(r.status, 1, `${kind}: ${r.stdout}`);
      assert.match(r.stderr, /refusing to serve plaintext/);
      assert.ok(!r.stdout.includes('READY'), `${kind} must not reach READY`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('switch off: the entry changes nothing in the process (same as plain node server.js)', async () => {
  const dir = workdir();
  const entry = await start(dir, { STUB_FP: '1' });
  const direct = await start(dir, { STUB_FP: '1' }, 'server.js');
  try {
    const a = line(entry.out, 'FP');
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.equal(a, line(direct.out, 'FP'), 'http.createServer and net.Server#listen are the originals');
  } finally {
    entry.child.kill();
    direct.child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the fingerprint can see the patch: with TLS on it differs (so the off check above has teeth)', { skip: skipTls }, async () => {
  const dir = workdir();
  pki(dir);
  const env = { GENESIS_TLS_CERT: join(dir, 'tls.crt'), GENESIS_TLS_KEY: join(dir, 'tls.key') };
  const off = await start(dir, { STUB_FP: '1' }, 'server.js');
  const on = await start(dir, { STUB_FP: '1', ...env });
  try {
    assert.notEqual(line(on.out, 'FP'), line(off.out, 'FP'));
  } finally {
    off.child.kill();
    on.child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('external host (unknown CA): outbound behaviour is identical with the switch on and off, verify flag false included', { skip: skipTls }, async () => {
  const dir = workdir();
  pki(dir);
  // An "external" service signed by a CA the platform does not trust: self-signed.
  const external = https.createServer({ key: readFileSync(join(dir, 'o.key')), cert: readFileSync(join(dir, 'other.crt')) }, (q, r) => r.end('external'));
  await new Promise((r) => external.listen(0, '127.0.0.1', r));
  const extPort = String(external.address().port);
  const run = async (extraEnv, switchOn) => {
    const base = { STUB_OUT: '1', EXT_PORT: extPort, ...extraEnv };
    // On: the platform CA is added to Node's trust the way the chart does (additive).
    const r = switchOn
      ? await start(dir, { ...base, GENESIS_TLS_CERT: join(dir, 'tls.crt'), GENESIS_TLS_KEY: join(dir, 'tls.key'), NODE_EXTRA_CA_CERTS: join(dir, 'ca.crt') })
      : await start(dir, base);
    r.child.kill();
    return JSON.parse(line(r.out, 'OUT'));
  };
  try {
    const offDefault = await run({}, false);
    assert.deepEqual(await run({}, true), offDefault);
    assert.equal(offDefault.unverified, 'status 200', 'rejectUnauthorized:false still connects');
    assert.match(offDefault.verified, /^error (DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE)$/);
    assert.match(offDefault.fetch, /^error /);
    const offFlag = await run({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, false);
    assert.deepEqual(await run({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, true), offFlag);
    assert.deepEqual(offFlag, { unverified: 'status 200', verified: 'status 200', fetch: 'status 200' });
  } finally {
    external.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('A3: NODE_EXTRA_CA_CERTS adds the platform CA to the default roots and removes none', { skip: skipTls }, async () => {
  const dir = workdir();
  pki(dir);
  try {
    const base = await start(dir, { STUB_CA: '1' }, 'server.js');
    const extra = await start(dir, { STUB_CA: '1', NODE_EXTRA_CA_CERTS: join(dir, 'ca.crt') }, 'server.js');
    base.child.kill();
    extra.child.kill();
    const a = line(base.out, 'CA');
    if (a === 'unsupported') return; // tls.getCACertificates needs Node >= 22.15
    assert.equal(Number(line(extra.out, 'CA')), Number(a) + 1);
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
