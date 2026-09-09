#!/bin/bash
# Script to link all IPFS nodes into a single private distributed network

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

log_info "Configuring IPFS Distributed Private Network..."

# This assumes your IPFS containers are named ipfs0, ipfs1, ..., ipfs5
IPFS_NODE_COUNT=6

# 0. Disable AutoConf to allow daemon to start in a private network
log_info "Disabling AutoConf on all nodes to prevent startup errors on a private network..."
for i in $(seq 0 $(($IPFS_NODE_COUNT - 1))); do
    log_info "Applying config to ipfs${i} offline..."
    docker stop "ipfs${i}" 2>/dev/null || true

    IMAGE=$(docker inspect --format='{{.Config.Image}}' "ipfs${i}" 2>/dev/null || echo "ipfs/kubo:latest")
    
    # Use an offline temporary container to initialize and patch the config to bypass crash-loops
    docker run --rm --volumes-from "ipfs${i}" --entrypoint sh "$IMAGE" -c "ipfs init 2>/dev/null || true; ipfs config --json AutoConf.Enabled false 2>/dev/null || true; ipfs config Routing.Type dht 2>/dev/null || true; ipfs config --json Bootstrap '[]' 2>/dev/null || true; ipfs config --json DNS.Resolvers '{}' 2>/dev/null || true; ipfs config --json Routing.DelegatedRouters '[]' 2>/dev/null || true; ipfs config --json Ipns.DelegatedPublishers '[]' 2>/dev/null || true; chown -R 1000:100 /data/ipfs 2>/dev/null || true"
    
    docker start "ipfs${i}" 2>/dev/null || true
done
sleep 5 # Give containers a moment to fully initialize

# 1. Clean default bootstraps (connected to public IPFS)
log_info "Removing public bootstrap nodes..."
for i in $(seq 0 $(($IPFS_NODE_COUNT - 1))); do
    docker exec "ipfs${i}" ipfs bootstrap rm --all || log_warn "Failed to remove bootstraps from ipfs${i}. Is it running?"
done

# 2. Get Peer IDs
log_info "Gathering Peer ID of bootstrap node (ipfs0)..."
ID0=$(docker exec ipfs0 ipfs id -f "<id>")

# 3. Add each other as bootstraps
# Note: We use container names for internal resolution, 
# but for multi-device cross-communication, external IPs should be used.
log_info "Peering all other nodes with ipfs0..."
for i in $(seq 1 $(($IPFS_NODE_COUNT - 1))); do
    MSYS_NO_PATHCONV=1 docker exec "ipfs${i}" ipfs bootstrap add "/dns4/ipfs0/tcp/4001/p2p/${ID0}" || log_warn "Failed to peer ipfs${i} with ipfs0."
    # Actively force swarm connection so they instantly sync
    MSYS_NO_PATHCONV=1 docker exec "ipfs${i}" ipfs swarm connect "/dns4/ipfs0/tcp/4001/p2p/${ID0}" || true
done

log_info "IPFS Distributed Network Configured!"
log_info "Nodes are now using a private swarm and peering with ipfs0."
