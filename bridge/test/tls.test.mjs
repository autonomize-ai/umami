// Internal TLS listener (AUTPE-8197, part F2). Needs the `openssl` binary to mint
// a throwaway CA and leaf; the whole file skips where it is not installed.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { createListener, tlsOptionsFromEnv } from '../tls.mjs';

let haveOpenssl = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  haveOpenssl = false;
}
const skip = haveOpenssl ? false : 'openssl not installed';

function mint() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bridge-tls-'));
  const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=test ca', '-days', '2');
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'other.key', '-out', 'other.crt', '-subj', '/CN=other ca', '-days', '2');
  run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tls.key', '-out', 'leaf.csr', '-subj', '/CN=umami');
  fs.writeFileSync(path.join(dir, 'ext'), 'subjectAltName=DNS:genesis-umami.test.svc\n');
  run('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tls.crt', '-days', '2', '-extfile', 'ext');
  return dir;
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
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

const ok = (_req, res) => res.end('ok');

test('both variables unset: plain http, unchanged', async () => {
  assert.equal(tlsOptionsFromEnv({}), undefined);
  const server = createListener(ok, {});
  assert.ok(server instanceof http.Server && !(server instanceof https.Server));
  const port = await listen(server);
  const status = await new Promise((r) => http.get({ host: '127.0.0.1', port }, (res) => { res.resume(); r(res.statusCode); }));
  assert.equal(status, 200);
  server.close();
});

test('only one of cert and key set: throws, never falls back to http', () => {
  assert.throws(() => createListener(ok, { GENESIS_TLS_CERT: '/x' }), /must both be set/);
  assert.throws(() => createListener(ok, { GENESIS_TLS_KEY: '/y' }), /must both be set/);
});

test('unreadable files: throws', () => {
  assert.throws(
    () => createListener(ok, { GENESIS_TLS_CERT: '/nope/tls.crt', GENESIS_TLS_KEY: '/nope/tls.key' }),
    /cannot read TLS material: ENOENT/,
  );
});

test('tls on: verified client connects; wrong CA, wrong host and TLS 1.1 are refused', { skip }, async () => {
  const dir = mint();
  const env = { GENESIS_TLS_CERT: path.join(dir, 'tls.crt'), GENESIS_TLS_KEY: path.join(dir, 'tls.key') };
  // The floor is pinned, not left to the OpenSSL default (which also refuses 1.1
  // today, so the handshake check below alone would not catch the pin vanishing).
  assert.equal(tlsOptionsFromEnv(env).minVersion, 'TLSv1.2');
  const server = createListener(ok, env);
  assert.ok(server instanceof https.Server);
  const port = await listen(server);
  const ca = fs.readFileSync(path.join(dir, 'ca.crt'));

  assert.equal(await get(port, { ca, servername: 'genesis-umami.test.svc', headers: { host: 'x' } }), 200);
  await assert.rejects(get(port, { ca: fs.readFileSync(path.join(dir, 'other.crt')), servername: 'genesis-umami.test.svc' }), /unable to verify|self.signed|issuer/i);
  await assert.rejects(get(port, { ca, servername: 'some-other-name.svc' }), (e) => e.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
  await assert.rejects(
    get(port, { ca, servername: 'genesis-umami.test.svc', minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' }),
    (e) => /protocol version|no protocols|alert|wrong version/i.test(e.message),
  );
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
