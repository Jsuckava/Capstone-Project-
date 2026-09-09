#!/bin/bash
set -e

echo "=========================================="
echo "  Hyperledger Fabric Binaries Installer   "
echo "=========================================="

# Ensure the script runs inside the network directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[INFO] Downloading official Fabric install script..."
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
chmod +x install-fabric.sh

echo "[INFO] Installing Fabric v2.5.4 and Fabric CA v1.5.7 binaries into network/bin..."
./install-fabric.sh --fabric-version 2.5.4 --ca-version 1.5.7 binary

echo "[INFO] Cleaning up installation script..."
rm install-fabric.sh

echo "[SUCCESS] Installation complete! Binaries are located in: $(pwd)/bin"
echo "          You can now safely run ./full_deploy.sh"
echo "=========================================="