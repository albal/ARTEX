#!/usr/bin/env bash
# Development mode: the backend (:8787) + traffic proxy (:8788) run together with the frontend next dev (:5173).
# The frontend reverse-proxies /api to the backend; Ctrl-C exits everything.
#
# For the single-binary (embedded frontend) approach see the "single binary" section of the README, which does not use this script.
set -euo pipefail
cd "$(dirname "$0")"

# on exit, kill all child processes in this process group (backend + frontend).
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# the backend (plain go run, frontend not embedded); the number of concurrent work agents is configured in "System settings".
go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788 &

# the frontend with hot reload (Vite/Next dev server, /api reverse-proxied to :8787).
( cd web && npm run dev ) &

echo "[dev] backend :8787 / proxy :8788 / frontend http://localhost:5173  (Ctrl-C to exit)"
wait
