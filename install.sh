#!/usr/bin/env bash
# ARTEX install script: ① all-Docker  ② local build and run
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# ── docker environment detection / auto-install ───────────────────
ensure_docker(){
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "docker and docker compose detected"; return
  fi
  warn "docker / docker compose not detected"
  case "$(uname -s)" in
    Linux)
      if [ "$(ask 'auto-install Docker? (y/n)' y)" = y ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER" || true
        ok "Docker installed (the group change needs a re-login to use it without sudo)"
      else
        die "please install docker yourself and retry"
      fi ;;
    Darwin) die "on macOS please install Docker Desktop: https://www.docker.com/products/docker-desktop/" ;;
    *)      die "please install docker yourself and retry" ;;
  esac
}

# ── ① all-Docker ───────────────────────────────
install_docker(){
  ensure_docker
  if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || true
    local pw key
    pw="$(ask 'Postgres password (Enter to generate a random one)' "$(rand)")"
    key="$(ask 'ANTHROPIC_API_KEY (may be left blank, configured later in the UI)' '')"
    sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pw}|" .env
    sed -i.bak "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${key}|" .env
    rm -f .env.bak
    ok "generated .env (POSTGRES_PASSWORD set)"
  else
    info "using the existing .env"
  fi
  info "pulling the images and starting…"
  docker compose pull || true
  docker compose up -d
  ok "startup complete → http://localhost:8787"
  info "view the logs: docker compose logs -f artex"
}

# ── ② local build and run ──────────────────────────────
install_local(){
  echo "database install method:"
  echo "  1) connect to an existing PostgreSQL"
  echo "  2) start a PostgreSQL with Docker (needs docker)"
  case "$(ask 'choose' 1)" in
    2)
      ensure_docker
      local pw; pw="$(ask 'Postgres password (Enter for random)' "$(rand)")"
      docker run -d --name artex-pg -p 5432:5432 \
        -e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=artex \
        -v artex-pg:/var/lib/postgresql/data postgres:16-alpine
      DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=artex DB_PASS="$pw" DB_NAME=artex DB_SSL=disable ;;
    *)
      DB_HOST="$(ask 'database host' 127.0.0.1)"
      DB_PORT="$(ask 'port' 5432)"
      DB_USER="$(ask 'user' artex)"
      DB_PASS="$(ask 'password' '')"
      DB_NAME="$(ask 'database name' artex)"
      DB_SSL="$(ask 'sslmode (disable/require)' disable)" ;;
  esac

  # generate config.json
  cat > config.json <<JSON
{
  "database": {
    "host": "${DB_HOST}",
    "port": ${DB_PORT},
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "dbname": "${DB_NAME}",
    "sslmode": "${DB_SSL}"
  }
}
JSON
  ok "generated config.json"

  # go environment check
  command -v go >/dev/null 2>&1 || die "Go not detected, please install Go (>=1.26): https://go.dev/dl/"
  ok "Go: $(go version)"

  # embedding the frontend needs node to produce the static artefacts
  if command -v npm >/dev/null 2>&1; then
    info "building the frontend static artefacts…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "compiling the embedded single binary…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "npm not detected: will compile the backend **without an embedded frontend** (the frontend must run separately via npm run dev)"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "compiled → ./artex"

  info "starting… (Ctrl-C to exit)"
  ./artex
}

echo "=============================="
echo "  ARTEX install"
echo "  1) all-Docker install"
echo "  2) local run (go build)"
echo "=============================="
case "$(ask 'choose' 1)" in
  1) install_docker ;;
  2) install_local ;;
  *) die "invalid choice" ;;
esac
