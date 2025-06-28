#!/usr/bin/env bash
# install_services.sh  –  exécuter en root

set -euo pipefail

## ── 0. Variables modifiables ──────────────────────────────────────────────
APP_DIR="/root/NovaSentinel"               # racine du dépôt
FRONT_DIR="$APP_DIR/client/frontend"                # où se trouve package.json
API_MODULE="script.api:app"           # chemin Python de l'API
PORT_API=8000
PORT_WEB=3000

## ── 1. Dépendances OS minimales ───────────────────────────────────────────
apt-get update
apt-get install -y curl git python3-venv

## ── 2. Node 20 + pnpm pour le front ───────────────────────────────────────
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs
corepack enable
corepack prepare pnpm@latest --activate

## ── 3. Python venv + libs pour l’API ──────────────────────────────────────
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install fastapi "uvicorn[standard]" requests dnspython \
                               python-nmap python-dotenv

## ── 4. Build (ou install) du front ────────────────────────────────────────
cd "$FRONT_DIR"
pnpm install
pnpm build                                # => .next/

## ── 5. Unit systemd : API ─────────────────────────────────────────────────
cat >/etc/systemd/system/nova-api.service <<EOF
[Unit]
Description=NovaSentinel API (FastAPI)
After=network.target

[Service]
WorkingDirectory=$APP_DIR
Environment=PYTHONPATH=$APP_DIR/client/core
ExecStart=$APP_DIR/venv/bin/uvicorn $API_MODULE --host 0.0.0.0 --port $PORT_API
Restart=always
User=root
Group=root
EOF

## ── 6. Unit systemd : WEB ─────────────────────────────────────────────────
cat >/etc/systemd/system/nova-web.service <<EOF
[Unit]
Description=NovaSentinel Front (Next.js)
After=network.target

[Service]
WorkingDirectory=$FRONT_DIR
ExecStart=$(command -v pnpm) start -p $PORT_WEB
Environment=NODE_ENV=production
Restart=always
User=root
Group=root
EOF

## ── 7. Activation / démarrage ────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now nova-api.service
systemctl enable --now nova-web.service

echo -e "\n✅ Services lancés :\n  • API  : http://<IP>:$PORT_API/scan\n  • Front: http://<IP>:$PORT_WEB/\n"
