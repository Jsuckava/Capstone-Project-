#!/bin/bash

# Join every configured orderer to the application channel.

set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="${K8S_PROFILE:-local}"
CHANNEL_NAME="${1:-registrar-channel}"
CLI_NAMESPACE="plv-main-campus"
CLI_LABEL="app=fabric-cli"
CHANNEL_BLOCK="/opt/fabric-config/network/channel-artifacts/registrar-channel.block"
ORDERER_TLS_DIR="/var/hyperledger/orderer/tls"

if [[ "$PROFILE" == "local" ]]; then
    export KUBECTL_REMOTE_COMMAND_WEBSOCKETS="${KUBECTL_REMOTE_COMMAND_WEBSOCKETS:-false}"
fi

if [[ "$PROFILE" == "production" ]]; then
    # The Channel Participation API uses the mTLS admin listener on 7053.
    # Port 9443 is the operations/metrics endpoint, not the admin API.
    # This requires ORDERER_ADMIN_TLS_ENABLED=true in the orderer's environment.
    ORDERER_ENDPOINTS=(
        orderer-1.plv-main-campus.svc.cluster.local:7053
        orderer-2.plv-main-campus.svc.cluster.local:7053
        orderer-3.plv-annex-campus.svc.cluster.local:7053
        orderer-4.plv-annex-campus.svc.cluster.local:7053
        orderer-5.plv-pubad-campus.svc.cluster.local:7053
        orderer-6.plv-pubad-campus.svc.cluster.local:7053
    )
else
    # For local development, use the non-TLS admin port.
    ORDERER_ENDPOINTS=(
        orderer-1.plv-main-campus.svc.cluster.local:7053
        orderer-2.plv-main-campus.svc.cluster.local:7053
        orderer-3.plv-annex-campus.svc.cluster.local:7053
    )
fi

wait_for_pod() {
    local namespace="$1"
    local label="$2"
    local pod=""

    for _ in $(seq 1 60); do
        pod="$(kubectl get pods -n "$namespace" -l "$label" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
        if [[ -n "$pod" ]]; then
            kubectl wait --for=condition=Ready "pod/$pod" -n "$namespace" --timeout=120s >/dev/null
            printf '%s\n' "$pod"
            return 0
        fi
        sleep 2
    done

    echo "ERROR: Timed out waiting for pod with label $label in $namespace." >&2
    return 1
}

osnadmin_exec() {
    if [[ "$PROFILE" == "production" ]]; then
        # For production, provide client TLS certificates for mutual TLS with the orderer admin endpoint.
        kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- \
            osnadmin "$@" \
            --client-cert "$ORDERER_TLS_DIR/server.crt" \
            --client-key "$ORDERER_TLS_DIR/server.key" \
            --ca-file "$ORDERER_TLS_DIR/ca.crt"
    else # Local profile
        kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- osnadmin "$@"
    fi
}

orderer_has_channel() {
    local endpoint="$1"
    local output

    output="$(osnadmin_exec channel list -o "$endpoint" 2>/dev/null || true)"
    grep -Fq "$CHANNEL_NAME" <<<"$output"
}

join_orderer() {
    local endpoint="$1"

    if orderer_has_channel "$endpoint"; then
        echo "[SKIP] $endpoint is already joined to $CHANNEL_NAME."
        return 0
    fi

    echo "[JOIN] Adding $endpoint to $CHANNEL_NAME..."
    if ! osnadmin_exec channel join \
        --channelID "$CHANNEL_NAME" \
        --config-block "$CHANNEL_BLOCK" \
        -o "$endpoint"; then
        if orderer_has_channel "$endpoint"; then
            echo "[OK] $endpoint joined despite a repeated-request response."
            return 0
        fi
        echo "ERROR: Failed to join $endpoint to $CHANNEL_NAME." >&2
        return 1
    fi

    orderer_has_channel "$endpoint" || {
        echo "ERROR: $endpoint did not report channel $CHANNEL_NAME after joining." >&2
        return 1
    }
}

echo "======================================"
echo "Fabric Orderer Channel Initialization"
echo "======================================"
echo "Channel: $CHANNEL_NAME"

CLI_POD="$(wait_for_pod "$CLI_NAMESPACE" "$CLI_LABEL")"
echo "CLI pod: $CLI_POD"

for endpoint in "${ORDERER_ENDPOINTS[@]}"; do
    join_orderer "$endpoint"
done

echo "All orderers are joined to $CHANNEL_NAME."
