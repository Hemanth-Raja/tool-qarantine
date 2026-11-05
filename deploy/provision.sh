#!/usr/bin/env bash
# One-shot provisioning for a fresh Vultr Ubuntu 24.04 VM.
#   ssh root@<vm-ip> 'bash -s' < deploy/provision.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y docker.io docker-compose-plugin git
systemctl enable --now docker
# Build the sandbox + sinkhole images the orchestrator needs.
cd /opt
[ -d tool-quarantine ] || git clone "${TQ_REPO:-https://github.com/REPLACE_ME/tool-quarantine}" tool-quarantine
cd tool-quarantine
docker build -t tq-sandbox:latest sandbox/
docker build -t tq-sinkhole:latest sinkhole/
docker compose -f deploy/docker-compose.yml up -d --build
echo "Tool Quarantine is up on http://$(curl -s ifconfig.me)/"
