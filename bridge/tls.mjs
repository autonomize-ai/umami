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
