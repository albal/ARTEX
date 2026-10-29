#!/usr/bin/env bash
# ARTEX update script: ① Docker update (pull the new image and rebuild)  ② local build update (rebuild the binary)
# The counterpart to install.sh: install does the first landing, update upgrades to a new version.
# DB migration needs no manual run — artex idempotently reruns schema.sql on every start-up (including ADD COLUMN/CREATE
# INDEX IF NOT EXISTS), so "restart = migrate". Data (the pgdata volume, ./data, ./skills) is unaffected.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# ── optional: sync the repo to the latest code (compose/scripts/local build source all rely on it) ───────
sync_repo(){
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "not a git working copy, skipping git pull"; return; }
  [ "$(ask 'pull the latest code (git pull --ff-only)? (y/n)' y)" = y ] || return
  if ! git pull --ff-only; then
    warn "git pull could not fast-forward (local changes or a diverged branch) — resolve it manually and retry; using the current code this time"
  fi
}

# ── ① Docker update ───────────────────────────────
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "docker / docker compose not detected, please deploy with ./install.sh first"
  [ -f .env ] || die ".env not found, please run ./install.sh to complete the first deployment first"

  # optional: upgrade to a specified version tag (if blank, keep ARTEX_TAG from .env, default latest)
  local tag; tag="$(ask 'target image tag (Enter to keep .env / latest)' '')"
  if [ -n "$tag" ]; then
    if grep -q '^ARTEX_TAG=' .env; then
      sed -i.bak "s|^ARTEX_TAG=.*|ARTEX_TAG=${tag}|" .env && rm -f .env.bak
    else
      printf '\nARTEX_TAG=%s\n' "$tag" >> .env
    fi
    ok "set ARTEX_TAG to ${tag}"
  fi

  # only touch artex: postgres is fixed at 16-alpine and need not be upgraded with it (pulling it is pure bandwidth waste,
  # and a major-version change carries compatibility risk). artex declares depends_on postgres, so bringing it
  # up by service name auto-starts pg if it is not running, and leaves a running one as is without rebuilding.
  info "pulling the new image (artex only)…"
  docker compose pull artex
  info "rebuilding and starting (artex auto-migrates the schema on restart)…"
  docker compose up -d artex
  ok "update complete → http://localhost:8787"
  info "view the logs: docker compose logs -f artex"
  info "clean up old images (optional): docker image prune -f"
}

# ── ② local build update ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "Go not detected (>=1.26): https://go.dev/dl/"
  [ -f config.json ] || warn "config.json not found — for a first deployment use ./install.sh instead"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "rebuilding the frontend static artefacts…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "recompiling the embedded single binary…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "npm not detected: compiling the backend **without an embedded frontend** (the frontend must run separately via npm run dev)"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "compiled → ./artex"
  warn "please restart the running artex process to take effect (it auto-migrates the schema on restart)"
}

echo "=============================="
echo "  ARTEX update"
echo "  1) Docker update (pull the new image and rebuild)"
echo "  2) local update (recompile with go)"
echo "=============================="
case "$(ask 'choose' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "invalid choice" ;;
esac
