#!/usr/bin/env bash
# Builds and starts the SSO server and the three applications locally.
# Press Ctrl+C to stop all of them.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p bin
for svc in sso-server catalog library forum; do
  go build -o "bin/$svc" "./services/$svc"
done

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT INT TERM

./bin/sso-server & pids+=($!)
sleep 1
./bin/catalog & pids+=($!)
./bin/library & pids+=($!)
./bin/forum   & pids+=($!)

echo "SSO server :8080, catalog :8081, library :8082, forum :8083 - Ctrl+C to stop"
wait
