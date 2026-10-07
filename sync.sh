#!/usr/bin/env bash
# Push this project to the CS60 SEED VM over SSH.
# Usage: bash sync.sh            (uses defaults below)
#        bash sync.sh <user> <vm-ip>
set -euo pipefail

VM_USER="${1:-seed}"
VM_IP="${2:-192.168.213.130}"
SRC="$(cd "$(dirname "$0")" && pwd)/"
DEST="~/networks_lab2/"

echo "Syncing $SRC -> $VM_USER@$VM_IP:$DEST"
rsync -av --exclude='__pycache__' --exclude='*.pyc' --exclude='.env' --exclude='.git' \
  "$SRC" "$VM_USER@$VM_IP:$DEST"
echo "Done. On the VM: cd ~/networks_lab2 && echo SECRET > .env && python3 server.py 8080"
