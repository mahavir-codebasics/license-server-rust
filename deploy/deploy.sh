#!/usr/bin/env bash
# Deploy license-server to the OCI ARM box over SSH.
#
#   ./deploy.sh [user@host]     (default: ubuntu@100.87.14.61, key ~/.ssh/oracle-docker-mahavir)
#
# What it does:
#   1. rsync the site bundle + compose + nginx config to ~/license-server/
#   2. generate secrets once into ~/license-server/.env (kept across redeploys)
#   3. ship the prebuilt images via `docker save | ssh docker load`
#   4. `docker compose up -d` and wait for /healthz
#
# Images must already be built locally (linux/arm64):
#   docker build -f docker/Dockerfile.api -t license-server-api:0.1.0 .
#   docker build -f docker/Dockerfile.ui  -t license-server-ui:0.1.0 \
#     --build-arg NEXT_PUBLIC_API_BASE_URL= .

set -euo pipefail

SSH_HOST="${1:-ubuntu@100.87.14.61}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/oracle-docker-mahavir}"
SSH="ssh -i $SSH_KEY -o BatchMode=yes $SSH_HOST"
REMOTE_DIR="license-server"

cd "$(dirname "$0")/.." # repo root

echo "▸ 1/4 sync config bundle"
rsync -az -e "ssh -i $SSH_KEY" \
  deploy/docker-compose.prod.yml deploy/nginx.conf "$SSH_HOST:$REMOTE_DIR/"  \
  --rsync-path="mkdir -p $REMOTE_DIR && rsync"
rsync -az -e "ssh -i $SSH_KEY" deploy/site/ "$SSH_HOST:$REMOTE_DIR/site/"

echo "▸ 2/4 ensure secrets"
$SSH "cd $REMOTE_DIR && if [ ! -f .env ]; then
    umask 077
    echo \"POSTGRES_PASSWORD=\$(openssl rand -hex 16)\"  >> .env
    echo \"MASTER_KEY=\$(openssl rand -hex 32)\"          >> .env
    echo 'generated new .env';
  else echo '.env exists (keeping)'; fi"

echo "▸ 3/4 ship images"
docker save license-server-api:0.1.0 license-server-ui:0.1.0 \
  | gzip | ssh -i "$SSH_KEY" "$SSH_HOST" 'gunzip | docker load'

echo "▸ 4/4 start stack"
$SSH "docker pull -q postgres:16-alpine >/dev/null; docker pull -q redis:7-alpine >/dev/null; docker pull -q nginx:1.27-alpine >/dev/null; cd $REMOTE_DIR && docker compose -f docker-compose.prod.yml up -d --remove-orphans"

echo "▸ waiting for healthz"
for i in $(seq 1 30); do
  if $SSH 'curl -sf http://localhost/healthz >/dev/null 2>&1'; then
    echo "✓ healthy: http://$(echo $SSH_HOST | cut -d@ -f2)/"
    exit 0
  fi
  sleep 2
done
echo "✗ stack did not become healthy in 60s — check: ssh $SSH_HOST 'cd $REMOTE_DIR && docker compose -f docker-compose.prod.yml ps && docker compose -f docker-compose.prod.yml logs --tail 50'"
exit 1
