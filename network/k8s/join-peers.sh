#!/bin/bash

# Join all organization peers to the application channel.

set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="${K8S_PROFILE:-local}"
CHANNEL_NAME="${1:-registrar-channel}"
ARTIFACTS_DIR="./channel-artifacts-final"
if [[ "$PROFILE" == "production" ]]; then
    ARTIFACTS_DIR="./channel-artifacts-k8s"
fi
CHANNEL_BLOCK="${ARTIFACTS_DIR}/${CHANNEL_NAME}.block"

if [[ "$PROFILE" == "local" ]]; then
    export KUBECTL_REMOTE_COMMAND_WEBSOCKETS="${KUBECTL_REMOTE_COMMAND_WEBSOCKETS:-false}"
fi

[[ -f "$CHANNEL_BLOCK" ]] || {
    echo "ERROR: Channel block not found: $CHANNEL_BLOCK" >&2
    exit 1
}

peer_exec() {
    local namespace="$1"
    local pod="$2"
    local msp_id="$3"
    local tls_override="$4"
    shift 4

    MSYS_NO_PATHCONV=1 kubectl exec -n "$namespace" "$pod" -- env \
        CORE_PEER_TLS_ENABLED=true \
        CORE_PEER_TLS_ROOTCERT_FILE=/var/hyperledger/tls/ca.crt \
        CORE_PEER_TLS_SERVERHOSTOVERRIDE="$tls_override" \
        CORE_PEER_LOCALMSPID="$msp_id" \
        CORE_PEER_MSPCONFIGPATH=/tmp/blockgo-admin-msp \
        CORE_PEER_ADDRESS=127.0.0.1:7051 \
        "$@"
}

join_peer() {
    local deployment="$1"
    local namespace="$2"
    local org="$3"
    local msp_id="$4"
    local peer_number="${5:-0}"
    local domain="${org}.capstone.com"
    local tls_override="peer${peer_number}.${domain}"
    local admin_msp="./crypto-config-final-v2/peerOrganizations/${domain}/users/Admin@${domain}/msp"
    local attempts=20

    [[ -d "$admin_msp" ]] || {
        echo "ERROR: Admin MSP not found: $admin_msp" >&2
        return 1
    }

    for attempt in $(seq 1 "$attempts"); do
        local pod
        local channels
        pod="$(kubectl get pods -n "$namespace" -l "app=$deployment" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"

        if [[ -n "$pod" ]] && kubectl wait --for=condition=Ready "pod/$pod" -n "$namespace" --timeout=30s >/dev/null 2>&1; then
            kubectl exec -n "$namespace" "$pod" -- rm -rf /tmp/blockgo-admin-msp >/dev/null
            kubectl cp "$admin_msp" "$namespace/$pod:/tmp/blockgo-admin-msp" >/dev/null

            channels="$(peer_exec "$namespace" "$pod" "$msp_id" "$tls_override" peer channel list 2>/dev/null || true)"
            if grep -Fq "$CHANNEL_NAME" <<<"$channels"; then
                echo "[SKIP] $deployment is already joined to $CHANNEL_NAME."
                return 0
            fi

            echo "[JOIN] Joining $deployment to $CHANNEL_NAME (attempt $attempt/$attempts)..."
            kubectl cp "$CHANNEL_BLOCK" "$namespace/$pod:/tmp/${CHANNEL_NAME}.block" >/dev/null
            if peer_exec "$namespace" "$pod" "$msp_id" "$tls_override" \
                peer channel join -b "/tmp/${CHANNEL_NAME}.block"; then
                echo "[OK] $deployment joined $CHANNEL_NAME."
                return 0
            fi
        fi

        sleep 5
    done

    echo "ERROR: Failed to join $deployment to $CHANNEL_NAME after $attempts attempts." >&2
    return 1
}

echo "======================================"
echo "Fabric Peer Channel Join"
echo "======================================"
echo "Channel: $CHANNEL_NAME"

join_peer "peer-registrar" "plv-main-campus" "registrar" "RegistrarMSP"
join_peer "peer-faculty" "plv-annex-campus" "faculty" "FacultyMSP"
join_peer "peer-department" "plv-pubad-campus" "department" "DepartmentMSP"

if [[ "$PROFILE" == "production" ]]; then
    join_peer "peer-registrar-2" "plv-main-campus" "registrar" "RegistrarMSP" 1
    join_peer "peer-faculty-2" "plv-annex-campus" "faculty" "FacultyMSP" 1
    join_peer "peer-department-2" "plv-pubad-campus" "department" "DepartmentMSP" 1
fi

echo "All peers are joined to $CHANNEL_NAME."
