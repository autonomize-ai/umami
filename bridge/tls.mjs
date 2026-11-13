// Internal TLS for the bridge listener (AUTPE-8197, part F2).
//
// The bridge is the only umami port reachable from other pods, so it is the one
// listener that has to speak TLS. It reads the platform's shared interface:
// GENESIS_TLS_CERT and GENESIS_TLS_KEY (PEM paths on the mounted Secret).
//
// Both unset: plain HTTP, exactly as before. Fail closed otherwise: one of the
// two set, or a file that cannot be read, throws. It never falls back to HTTP,
// because a pod that silently serves plaintext after the switch is on would pass
// its probes and fail the security review.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

/** TLS server options from the environment, or undefined when TLS is off. */
export function tlsOptionsFromEnv(env = process.env) {
  const certPath = env.GENESIS_TLS_CERT || '';
  const keyPath = env.GENESIS_TLS_KEY || '';
  if (!certPath && !keyPath) return undefined;
  if (!certPath || !keyPath) {
    throw new Error('GENESIS_TLS_CERT and GENESIS_TLS_KEY must both be set');
  }
  try {
    return {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      minVersion: 'TLSv1.2',
    };
  } catch (err) {
    throw new Error(`cannot read TLS material: ${err.code || err.message}`);
  }
}

/** http.createServer, or https.createServer when internal TLS is configured. */
export function createListener(handler, env = process.env) {
  const options = tlsOptionsFromEnv(env);
  return options ? https.createServer(options, handler) : http.createServer(handler);
}

/**
 * http.request or https.request for an upstream URL. The bridge reaches the app
 * on loopback; with internal TLS the app serves HTTPS there too, and trust comes
 * from NODE_EXTRA_CA_CERTS, so a failed verification is an upstream error, not a
 * silent downgrade.
 */
export function requestFor(url) {
  return String(url).startsWith('https:') ? https.request : http.request;
}

/**
 * TLS options for a request to an https upstream. Node verifies the server
 * certificate against the request's Host header when one is present, not against
 * the URL's host, and the bridge forwards the client's Host header (the public
 * hostname) to the app. Without an explicit servername every proxied request
 * fails verification and the user gets a 502. The bridge verifies against a name
 * it chooses: the upstream URL's own host. An IP host gets an empty servername,
 * which makes Node verify against the certificate's IP SANs rather than the
 * Host header (an IP is not a valid SNI name).
 */
export function upstreamTlsOptions(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:') return {};
  const host = u.hostname.replace(/^\[|\]$/g, '');
  return { servername: net.isIP(host) ? '' : host };
}

/**
 * The bridge's request to the app for a proxied client request: same method,
 * path and headers (including the client's Host), with the upstream TLS name
 * pinned by upstreamTlsOptions. server.mjs's proxy() calls this, so the tests
 * exercise the real path. `extra` is for tests (a CA); in the pod, trust comes
 * from NODE_EXTRA_CA_CERTS.
 */
export function proxyRequest(upstream, req, onResponse, extra = {}) {
  return requestFor(upstream)(
    upstream + req.url,
    { method: req.method, headers: req.headers, ...upstreamTlsOptions(upstream), ...extra },
    onResponse,
  );
}
