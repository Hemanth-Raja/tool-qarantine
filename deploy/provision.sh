#!/usr/bin/env bash
# One-shot provisioning for a fresh Vultr Ubuntu 24.04+ VM.
#   ssh root@<vm-ip> 'bash -s' < deploy/provision.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y docker.io git curl
# Ubuntu ships Compose v2 as docker-compose-v2; docker-compose-plugin is Docker's own repo.
apt-get install -y docker-compose-v2 || apt-get install -y docker-compose-plugin
systemctl enable --now docker
# Build the sandbox + sinkhole images the orchestrator needs.
cd /opt
[ -d tool-quarantine ] || git clone "${TQ_REPO:-https://github.com/Hemanth-Raja/tool-qarantine}" tool-quarantine
cd tool-quarantine
docker build -t tq-sandbox:latest sandbox/
docker build -t tq-sinkhole:latest sinkhole/
docker compose -f deploy/docker-compose.yml up -d --build
echo "Tool Quarantine is up on http://$(curl -s ifconfig.me)/"
