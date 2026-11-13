"use strict";
// Container entry for the Umami app (AUTPE-8197, part F2). Same pattern as the
// genesis-fe entry: Next's standalone server.js has no HTTPS option, and it
// builds its listener with one http.createServer call. When GENESIS_TLS_CERT and
// GENESIS_TLS_KEY are set this swaps that one call for https.createServer with
// minVersion TLSv1.2, restores the original at once, then loads the unmodified
// server.js. With both unset it is a pass-through.
//
// Fail closed, three ways. A half-set pair or an unreadable file exits 1. And
// swapping http.createServer only works while Next builds its listener through
// that one call, so a second guard watches every TCP listen: if anything other
// than a TLS server starts listening (a Next upgrade that builds its server
// another way), the process exits 1 instead of logging "TLS enabled" while
// serving plaintext. .cjs because the package is "type": "module" and the
// standalone server.js is CommonJS.
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const tls = require("node:tls");
const path = require("node:path");

// Switch state (DONE.md D11): GENESIS_TLS_CERT / KEY / CA absent = off; present and blank = refuse to
// start; present and set = on. Presence is tested with hasOwnProperty, never truthiness: a blank value
// is a misconfiguration, and treating it as "off" would serve plaintext from a pod believed encrypted.
const present = (name) => Object.prototype.hasOwnProperty.call(process.env, name);
const blank = ["GENESIS_TLS_CERT", "GENESIS_TLS_KEY", "GENESIS_TLS_CA"].filter(
  (n) => present(n) && process.env[n].trim() === "",
);
if (blank.length) {
  console.error(`${blank.join(", ")} is set but blank: unset it to turn internal TLS off, or give it a value`);
  process.exit(1);
}
const certPath = process.env.GENESIS_TLS_CERT;
const keyPath = process.env.GENESIS_TLS_KEY;

if (certPath !== undefined || keyPath !== undefined) {
  if (certPath === undefined || keyPath === undefined) {
    console.error("GENESIS_TLS_CERT and GENESIS_TLS_KEY must both be set");
    process.exit(1);
  }
  let cert;
  let key;
  try {
    cert = fs.readFileSync(certPath);
    key = fs.readFileSync(keyPath);
  } catch (err) {
    console.error(`Cannot read TLS material: ${err.code || err.message}`);
    process.exit(1);
  }

  const plainCreateServer = http.createServer;
  http.createServer = (...args) => {
    http.createServer = plainCreateServer;
    const listener = args.find((a) => typeof a === "function");
    return https.createServer({ key, cert, minVersion: "TLSv1.2" }, listener);
  };

  // Guard: a TCP listen on anything that is not a tls.Server is plaintext.
  // https.Server extends tls.Server, so the swapped-in listener passes.
  const plainListen = net.Server.prototype.listen;
  net.Server.prototype.listen = function (...args) {
    const first = args[0];
    const tcp =
      typeof first === "number" ||
      (typeof first === "string" && /^\d+$/.test(first)) ||
      (first !== null && typeof first === "object" && "port" in first);
    if (tcp && !(this instanceof tls.Server)) {
      console.error("Internal TLS is on but a plaintext TCP listener started; refusing to serve plaintext");
      process.exit(1);
    }
    return plainListen.apply(this, args);
  };
  console.log("Internal TLS enabled (TLSv1.2+)");
}

require(path.join(__dirname, "..", "server.js"));
