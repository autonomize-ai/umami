"use strict";
// Container entry for the Umami app (AUTPE-8197, part F2). Same pattern as the
// genesis-fe entry: Next's standalone server.js has no HTTPS option, and it
// builds its listener with one http.createServer call. When GENESIS_TLS_CERT and
// GENESIS_TLS_KEY are set this swaps that one call for https.createServer with
// minVersion TLSv1.2, restores the original at once, then loads the unmodified
// server.js. With both unset it is a pass-through.
//
// Fail closed: a half-set pair or an unreadable file exits 1. It never falls
// back to plain HTTP. .cjs because the package is "type": "module" and the
// standalone server.js is CommonJS.
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");

const certPath = process.env.GENESIS_TLS_CERT || "";
const keyPath = process.env.GENESIS_TLS_KEY || "";

if (certPath || keyPath) {
  if (!certPath || !keyPath) {
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
  console.log("Internal TLS enabled (TLSv1.2+)");
}

require(path.join(__dirname, "..", "server.js"));
