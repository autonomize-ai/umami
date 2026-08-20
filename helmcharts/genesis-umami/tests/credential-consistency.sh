#!/usr/bin/env bash
# Guards the one invariant helm-unittest cannot express: on a FIRST install
# (nothing in-cluster to look up) the generated Postgres password embedded in
# DATABASE_URL must equal POSTGRES_PASSWORD. They are two different Secret keys,
# and helm-unittest has no cross-field assertion — a shape/regex check passes
# happily while the two values disagree.
#
# Regression guarded: resolving the password separately per call site minted a
# fresh random each time, so Postgres initialised with one password while Umami
# connected with another and CrashLooped on auth. Kept honest by
# `umami.resolveOnce` memoising the value for the whole render.
#
# Usage: genesis/charts/umami/tests/credential-consistency.sh [chart-dir]
set -euo pipefail

CHART="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
RUNS=5
fail=0

for i in $(seq 1 "$RUNS"); do
  out=$(helm template consistency-check "$CHART" \
          --set enabled=true --show-only templates/secret.yaml)

  url_pw=$(printf '%s\n' "$out" | sed -n 's|.*DATABASE_URL: "postgresql://[^:]*:\([^@]*\)@.*|\1|p')
  pg_pw=$(printf '%s\n' "$out"  | sed -n 's|.*POSTGRES_PASSWORD: "\(.*\)"|\1|p')

  if [[ -z "$url_pw" || -z "$pg_pw" ]]; then
    echo "run $i: FAIL — could not extract credentials from the rendered Secret"
    fail=1
  elif [[ "$url_pw" != "$pg_pw" ]]; then
    echo "run $i: FAIL — DATABASE_URL password ($url_pw) != POSTGRES_PASSWORD ($pg_pw)"
    fail=1
  else
    echo "run $i: ok — both credentials resolve to the same generated value"
  fi
done

if (( fail )); then
  echo
  echo "FAILED: the bundled Postgres would reject Umami's connection on a first install."
  exit 1
fi

echo
echo "PASSED: $RUNS/$RUNS renders kept DATABASE_URL and POSTGRES_PASSWORD in agreement."
