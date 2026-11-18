#!/usr/bin/env bash
# Per-image TLS test, args: IMAGE. Boots the app (3000) and the bridge (3001) without the DB check, with a throwaway CA,
# as UID 65532, and checks TLS 1.2+ served, TLS 1.1 / wrong CA / wrong hostname / plaintext refused, the entry staying
# up, and a half-set config exiting non-zero. Needs docker, openssl, python3.
set -euo pipefail
IMAGE=${1:?usage: test-internal-tls-image.sh IMAGE}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
NAMES=()
VOL="umami-tls-test-$$-$RANDOM"
cleanup() { for n in "${NAMES[@]:-}"; do [ -n "$n" ] && docker rm -f "$n" >/dev/null 2>&1 || true; done; docker volume rm -f "$VOL" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

pki="$WORK/pki"; mkdir "$pki"
(
  cd "$pki"
  # Shaped like the platform's certificates: Python 3.13+ clients verify strictly (key identifiers, CA constraints).
  mkca() { openssl req -x509 -sha256 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.crt" -subj "/CN=$2" -days 2 -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null; }
  mkca ca "test ca"; mkca other "other ca"
  openssl req -newkey rsa:2048 -nodes -keyout tls.key -out l.csr -subj "/CN=genesis-umami" 2>/dev/null
  printf 'subjectAltName=DNS:genesis-umami,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' > ext
  openssl x509 -req -sha256 -in l.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 2 -extfile ext 2>/dev/null
  chmod 644 ./*.key ./*.crt   # throwaway material
)
# The files reach the containers through a named volume filled with `docker cp`, which works with a remote (dind)
# daemon; a bind mount of this agent's temp dir would be empty there.
docker volume create "$VOL" >/dev/null
docker create --name "$VOL-fill" -v "$VOL:/d" --entrypoint true "$IMAGE" >/dev/null
docker cp "$pki/." "$VOL-fill:/d/"
docker rm -f "$VOL-fill" >/dev/null
TLS_ENV=(-e GENESIS_TLS_CERT=/etc/genesis/internal-tls/tls.crt -e GENESIS_TLS_KEY=/etc/genesis/internal-tls/tls.key -e GENESIS_TLS_CA=/etc/genesis/internal-tls/ca.crt)
APP_ENV=(-e DATABASE_URL=postgresql://u:p@127.0.0.1:1/umami -e APP_SECRET=test -e PORT=3000 -e HOSTNAME=0.0.0.0)

half_set() { # label, command...
  local label=$1; shift
  set +e
  timeout 60 docker run --rm --user 65532:65532 "${APP_ENV[@]}" -e GENESIS_TLS_CERT=/etc/genesis/internal-tls/tls.crt --entrypoint node "$IMAGE" "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then echo "FAIL $label: half-set config did not exit non-zero (rc=$rc)"; exit 1; fi
  echo "ok   $label: half-set config exits $rc"
}

probe_listener() { # label, container-port, log-marker, path, max-status, command...
  local label=$1 cport=$2 marker=$3 path=$4 maxs=$5; shift 5
  local name="umami-tls-test-$$-$cport"; NAMES+=("$name")
  echo "== $label: boot $IMAGE with TLS"
  docker run -d --name "$name" --user 65532:65532 "${TLS_ENV[@]}" "${APP_ENV[@]}" -e BRIDGE_PORT="$cport" \
    -v "$VOL:/etc/genesis/internal-tls:ro" -p "127.0.0.1::$cport" --entrypoint node "$IMAGE" "$@" >/dev/null
  for _ in $(seq 1 60); do
    docker logs "$name" 2>&1 | grep -q "$marker" && break
    [ "$(docker inspect -f '{{.State.Running}}' "$name")" = "true" ] || { echo "FAIL $label exited:"; docker logs "$name" 2>&1 | tail -10; exit 1; }
    sleep 1
  done
  docker logs "$name" 2>&1 | grep -q "$marker" || { echo "FAIL $label never logged \"$marker\":"; docker logs "$name" 2>&1 | tail -10; exit 1; }
  sleep 2
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = "true" ] || { echo "FAIL $label exited after logging TLS enabled:"; docker logs "$name" 2>&1 | tail -10; exit 1; }
  echo "ok   $label: logged \"$marker\" and the container stays up"
  local port; port=$(docker port "$name" "$cport/tcp" | head -n1 | sed 's/.*://')
  local ready=0
  for _ in $(seq 1 90); do
    if python3 - "$port" <<'PY' 2>/dev/null
import socket, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3) as raw:
    ctx.wrap_socket(raw, server_hostname="genesis-umami").close()
PY
    then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "FAIL $label: no TLS handshake completed within 90s"; docker logs "$name" 2>&1 | tail -20; exit 1; }
  python3 "$HERE/internal_tls_probe.py" 127.0.0.1 "$port" "$pki/ca.crt" "$pki/other.crt" genesis-umami "$path" "$maxs"
}

half_set "app entry" scripts/tls-server.cjs
half_set "bridge" bridge/server.mjs

# A present but blank variable must exit non-zero, never be read as off.
blank_case() { # label, command...
  local label=$1; shift
  for v in GENESIS_TLS_CERT GENESIS_TLS_KEY GENESIS_TLS_CA; do
    set +e
    timeout 60 docker run --rm --user 65532:65532 "${APP_ENV[@]}" -e "$v=" --entrypoint node "$IMAGE" "$@" >/dev/null 2>&1
    local rc=$?
    set -e
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then echo "FAIL $label: blank $v did not exit non-zero (rc=$rc)"; exit 1; fi
    echo "ok   $label: blank $v exits $rc"
  done
}
blank_case "app entry" scripts/tls-server.cjs
blank_case "bridge" bridge/server.mjs
probe_listener "app (3000)" 3000 "Internal TLS enabled" / 999 scripts/tls-server.cjs
probe_listener "bridge (3001)" 3001 "over TLS" /bridge-healthz 200 bridge/server.mjs
echo "PASS $IMAGE"
