# syntax=docker/dockerfile:1
#
# Runtime image (no compilation in the image): installs only common tools and drops in the **pre-compiled Linux single binary**.
# The binary is cross-compiled by CI's binaries job (pure Go, no QEMU) and placed by target architecture at
# dist/<TARGETARCH>/artex in the build context. This way a multi-arch build only emulates the apt layer for arm64,
# no longer emulating the Next/Go compile, which is far faster.
#
# When building the image manually in local development, prepare the binary yourself first:
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add or remove as needed).
# Node is installed from NodeSource 20.x: bookworm's own apt nodejs is 18, and Playwright requires >=20.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Pre-install the Playwright MCP and CLI (globally), so the runtime no longer npx-downloads them over the network.
# @playwright/mcp: the browser MCP runs directly via `npx @playwright/mcp` (already globally installed, no -y/@latest needed).
# @playwright/cli: provides playwright-cli, with a --help after install to verify it is executable.
# also install playwright (which provides browser management), then --with-deps to pre-provision chromium and its system dependencies,
# so the in-container MCP/CLI works on first launch without downloading the browser over the network.
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# the pre-compiled binary for the matching architecture (dist/amd64/artex or dist/arm64/artex)
COPY dist/${TARGETARCH}/artex /app/artex
# the supervisor launch script: after the process exits it decides from the exit code whether to relaunch, and the web UI one-click update relies on it to complete the swap.
# it also forwards SIGTERM to artex — docker stop only sends the signal to PID 1,
# and without forwarding artex would not receive it, could not shut down gracefully, and would be hard-killed by SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/ (SQLite + jwt.key) persistence point
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
