#!/bin/bash

# Package, install, approve, commit, and initialize the CCaaS chaincode.

set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="${K8S_PROFILE:-local}"
CHANNEL_NAME="${CHANNEL_NAME:-registrar-channel}"
CC_NAME="${CHAINCODE_NAME:-registrar}"
CC_LABEL="${CHAINCODE_LABEL:-registrar_1.0}"
CC_VERSION="${CHAINCODE_VERSION:-1.0}"
CC_SEQUENCE="${CHAINCODE_SEQUENCE:-1}"
CLI_NAMESPACE="plv-main-campus"
REMOTE_DIR="/tmp/blockgo-chaincode-bootstrap"
ORDERER_ENDPOINT="orderer-1.plv-main-campus.svc.cluster.local:7050"
ORDERER_TLS_OVERRIDE="orderer.capstone.com"
CHAINCODE_PACKAGE_ANNOTATION="blockgo.plv/chaincode-package-id"

if [[ "$PROFILE" == "local" ]]; then
    export KUBECTL_REMOTE_COMMAND_WEBSOCKETS="${KUBECTL_REMOTE_COMMAND_WEBSOCKETS:-false}"
fi

ORGS=(registrar faculty department)
NAMESPACES=(plv-fabric plv-main-campus plv-annex-campus plv-pubad-campus)

declare -A ORG_NAMESPACE=(
    [registrar]="plv-main-campus"
    [faculty]="plv-annex-campus"
    [department]="plv-pubad-campus"
)
declare -A ORG_MSP=(
    [registrar]="RegistrarMSP"
    [faculty]="FacultyMSP"
    [department]="DepartmentMSP"
)
declare -A ORG_PEER_HOST=(
    [registrar]="peer0.registrar.capstone.com"
    [faculty]="peer0.faculty.capstone.com"
    [department]="peer0.department.capstone.com"
)
declare -A ORG_PEER_SERVICE=(
    [registrar]="peer-registrar"
    [faculty]="peer-faculty"
    [department]="peer-department"
)
declare -A ORG_SECONDARY_PEER_HOST=(
    [registrar]="peer1.registrar.capstone.com"
    [faculty]="peer1.faculty.capstone.com"
    [department]="peer1.department.capstone.com"
)
declare -A ORG_SECONDARY_PEER_SERVICE=(
    [registrar]="peer-registrar-2"
    [faculty]="peer-faculty-2"
    [department]="peer-department-2"
)
declare -A ORG_CHAINCODE_SERVICE=(
    [registrar]="registrar-chaincode"
    [faculty]="faculty-chaincode"
    [department]="department-chaincode"
)
declare -A ORG_CHAINCODE_DEPLOYMENT=(
    [registrar]="registrar-chaincode"
    [faculty]="faculty-chaincode"
    [department]="department-chaincode"
)
declare -A PACKAGE_FILES
declare -A PACKAGE_IDS

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/blockgo-ccpkg.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

require_file() {
    [[ -f "$1" ]] || {
        echo "ERROR: Required file not found: $1" >&2
        exit 1
    }
}

require_file "./crypto-config-final-v2/chaincode-tls/ca-bundle/ca-bundle.pem"
require_file "./crypto-config-final-v2/ordererOrganizations/capstone.com/orderers/orderer.capstone.com/tls/ca.crt"

# Fabric expects root_cert to contain PEM text. Escape its line endings for JSON;
# base64-encoding the entire PEM makes the peer fail with "error adding root certificate".
ROOT_CERT="$(awk '{ sub(/\r$/, ""); printf "%s\\n", $0 }' \
    ./crypto-config-final-v2/chaincode-tls/ca-bundle/ca-bundle.pem)"

create_package() {
    local org="$1"
    local package_dir="$WORK_DIR/$org"
    local package_file="$WORK_DIR/${org}.tar.gz"

    mkdir -p "$package_dir"
    printf '%s\n' \
        '{' \
        "  \"address\": \"${ORG_CHAINCODE_SERVICE[$org]}:9999\"," \
        '  "dial_timeout": "10s",' \
        '  "tls_required": true,' \
        '  "client_auth_required": false,' \
        "  \"root_cert\": \"${ROOT_CERT}\"" \
        '}' > "$package_dir/connection.json"
    printf '%s\n' \
        '{' \
        '  "type": "ccaas",' \
        "  \"label\": \"${CC_LABEL}\"" \
        '}' > "$package_dir/metadata.json"

    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        -czf "$package_dir/code.tar.gz" -C "$package_dir" connection.json
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        -czf "$package_file" -C "$package_dir" code.tar.gz metadata.json

    PACKAGE_FILES[$org]="$package_file"
    PACKAGE_IDS[$org]="${CC_LABEL}:$(sha256sum "$package_file" | awk '{print $1}')"
}

for org in "${ORGS[@]}"; do
    create_package "$org"
done

if [[ "${1:-}" == "--print-package-ids" ]]; then
    printf 'CHAINCODE_ID_REGISTRAR=%s\n' "${PACKAGE_IDS[registrar]}"
    printf 'CHAINCODE_ID_FACULTY=%s\n' "${PACKAGE_IDS[faculty]}"
    printf 'CHAINCODE_ID_DEPARTMENT=%s\n' "${PACKAGE_IDS[department]}"
    exit 0
fi

wait_for_cli() {
    local pod=""

    for _ in $(seq 1 60); do
        pod="$(kubectl get pods -n "$CLI_NAMESPACE" -l app=fabric-cli -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
        if [[ -n "$pod" ]]; then
            kubectl wait --for=condition=Ready "pod/$pod" -n "$CLI_NAMESPACE" --timeout=120s >/dev/null
            printf '%s\n' "$pod"
            return 0
        fi
        sleep 2
    done

    echo "ERROR: Timed out waiting for the Fabric CLI pod." >&2
    return 1
}

peer_exec_at() {
    local org="$1"
    local peer_host="$2"
    local tls_host_override="${PEER_TLS_HOST_OVERRIDE-$peer_host}"
    shift 2

    MSYS_NO_PATHCONV=1 kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- env \
        CORE_PEER_TLS_ENABLED=true \
        CORE_PEER_TLS_ROOTCERT_FILE="$REMOTE_DIR/$org/peer-tls-ca.crt" \
        CORE_PEER_TLS_SERVERHOSTOVERRIDE="$tls_host_override" \
        CORE_PEER_LOCALMSPID="${ORG_MSP[$org]}" \
        CORE_PEER_MSPCONFIGPATH="$REMOTE_DIR/$org/admin-msp" \
        CORE_PEER_ADDRESS="${peer_host}:7051" \
        "$@"
}

peer_exec() {
    local org="$1"
    shift
    peer_exec_at "$org" "${ORG_PEER_HOST[$org]}" "$@"
}

stage_cli_files() {
    kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- \
        sh -c "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'" >/dev/null

    kubectl cp \
        ./crypto-config-final-v2/ordererOrganizations/capstone.com/orderers/orderer.capstone.com/tls/ca.crt \
        "$CLI_NAMESPACE/$CLI_POD:$REMOTE_DIR/orderer-tls-ca.crt" -c cli >/dev/null

    for org in "${ORGS[@]}"; do
        local namespace="${ORG_NAMESPACE[$org]}"
        local domain="${org}.capstone.com"
        local admin_msp="./crypto-config-final-v2/peerOrganizations/${domain}/users/Admin@${domain}/msp"
        local peer_ca="./crypto-config-final-v2/peerOrganizations/${domain}/peers/${ORG_PEER_HOST[$org]}/tls/ca.crt"
        local service_ip

        [[ -d "$admin_msp" ]] || {
            echo "ERROR: Admin MSP not found: $admin_msp" >&2
            return 1
        }
        require_file "$peer_ca"

        kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- \
            mkdir -p "$REMOTE_DIR/$org" >/dev/null
        kubectl cp "$admin_msp" \
            "$CLI_NAMESPACE/$CLI_POD:$REMOTE_DIR/$org/admin-msp" -c cli >/dev/null
        kubectl cp "$peer_ca" \
            "$CLI_NAMESPACE/$CLI_POD:$REMOTE_DIR/$org/peer-tls-ca.crt" -c cli >/dev/null
        kubectl cp "${PACKAGE_FILES[$org]}" \
            "$CLI_NAMESPACE/$CLI_POD:$REMOTE_DIR/$org.tar.gz" -c cli >/dev/null

        service_ip="$(kubectl get service "${ORG_PEER_SERVICE[$org]}" -n "$namespace" -o jsonpath='{.spec.clusterIP}')"
        [[ -n "$service_ip" ]] || {
            echo "ERROR: Could not resolve ClusterIP for ${ORG_PEER_SERVICE[$org]} in $namespace." >&2
            return 1
        }
        kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- sh -c \
            "grep -Fq '${ORG_PEER_HOST[$org]}' /etc/hosts || printf '\n%s %s\n' '$service_ip' '${ORG_PEER_HOST[$org]}' >> /etc/hosts"

        if [[ "$PROFILE" == "production" ]]; then
            service_ip="$(kubectl get service "${ORG_SECONDARY_PEER_SERVICE[$org]}" -n "$namespace" -o jsonpath='{.spec.clusterIP}')"
            [[ -n "$service_ip" ]] || {
                echo "ERROR: Could not resolve secondary peer service for $org." >&2
                return 1
            }
            kubectl exec -n "$CLI_NAMESPACE" "$CLI_POD" -c cli -- sh -c \
                "grep -Fq '${ORG_SECONDARY_PEER_HOST[$org]}' /etc/hosts || printf '\n%s %s\n' '$service_ip' '${ORG_SECONDARY_PEER_HOST[$org]}' >> /etc/hosts"
        fi
    done
}

install_packages() {
    for org in "${ORGS[@]}"; do
        local peer_hosts=("${ORG_PEER_HOST[$org]}")
        if [[ "$PROFILE" == "production" ]]; then
            peer_hosts+=("${ORG_SECONDARY_PEER_HOST[$org]}")
        fi
        local peer_host
        for peer_host in "${peer_hosts[@]}"; do
            local installed
            installed="$(peer_exec_at "$org" "$peer_host" peer lifecycle chaincode queryinstalled)"
            if grep -Fq "${PACKAGE_IDS[$org]}" <<<"$installed"; then
                echo "[SKIP] $peer_host already has ${PACKAGE_IDS[$org]}."
                continue
            fi

            echo "[INSTALL] Installing the $org CCaaS package on $peer_host..."
            peer_exec_at "$org" "$peer_host" peer lifecycle chaincode install "$REMOTE_DIR/$org.tar.gz"
        done
    done
}

sync_chaincode_ids() {
    local registrar_id faculty_id department_id payload
    registrar_id="$(printf '%s' "${PACKAGE_IDS[registrar]}" | base64 | tr -d '\r\n')"
    faculty_id="$(printf '%s' "${PACKAGE_IDS[faculty]}" | base64 | tr -d '\r\n')"
    department_id="$(printf '%s' "${PACKAGE_IDS[department]}" | base64 | tr -d '\r\n')"
    payload="{\"data\":{\"CHAINCODE_ID_REGISTRAR\":\"$registrar_id\",\"CHAINCODE_ID_FACULTY\":\"$faculty_id\",\"CHAINCODE_ID_DEPARTMENT\":\"$department_id\"}}"

    for namespace in "${NAMESPACES[@]}"; do
        kubectl patch secret blockgo-secrets -n "$namespace" --type=merge -p "$payload" >/dev/null
    done

    if [[ "$PROFILE" == "local" ]]; then
        for org in "${ORGS[@]}"; do
            kubectl patch "deployment/${ORG_CHAINCODE_DEPLOYMENT[$org]}" \
                -n "${ORG_NAMESPACE[$org]}" --type=merge \
                -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}' >/dev/null
        done
    fi

    for org in "${ORGS[@]}"; do
        local deployed_package_id
        deployed_package_id="$(
            kubectl get "deployment/${ORG_CHAINCODE_DEPLOYMENT[$org]}" \
                -n "${ORG_NAMESPACE[$org]}" \
                -o "jsonpath={.metadata.annotations['blockgo\\.plv/chaincode-package-id']}" \
                2>/dev/null || true
        )"

        if [[ "$deployed_package_id" == "${PACKAGE_IDS[$org]}" ]]; then
            echo "[SKIP] ${ORG_CHAINCODE_DEPLOYMENT[$org]} already runs ${PACKAGE_IDS[$org]}."
            continue
        fi

        kubectl rollout restart "deployment/${ORG_CHAINCODE_DEPLOYMENT[$org]}" -n "${ORG_NAMESPACE[$org]}" >/dev/null
        kubectl rollout status "deployment/${ORG_CHAINCODE_DEPLOYMENT[$org]}" -n "${ORG_NAMESPACE[$org]}" --timeout=5m
        kubectl annotate "deployment/${ORG_CHAINCODE_DEPLOYMENT[$org]}" \
            -n "${ORG_NAMESPACE[$org]}" \
            "${CHAINCODE_PACKAGE_ANNOTATION}=${PACKAGE_IDS[$org]}" --overwrite >/dev/null
    done
}

approve_for_org() {
    local org="$1"
    local approved
    approved="$(peer_exec "$org" peer lifecycle chaincode queryapproved \
        --channelID "$CHANNEL_NAME" --name "$CC_NAME" \
        --sequence "$CC_SEQUENCE" --output json 2>/dev/null || true)"

    if grep -Fq "${PACKAGE_IDS[$org]}" <<<"$approved"; then
        echo "[SKIP] ${ORG_MSP[$org]} already approved the current package."
        return 0
    fi

    echo "[APPROVE] Approving chaincode for ${ORG_MSP[$org]}..."
    peer_exec "$org" peer lifecycle chaincode approveformyorg \
        --orderer "$ORDERER_ENDPOINT" \
        --ordererTLSHostnameOverride "$ORDERER_TLS_OVERRIDE" \
        --tls --cafile "$REMOTE_DIR/orderer-tls-ca.crt" \
        --channelID "$CHANNEL_NAME" \
        --name "$CC_NAME" \
        --version "$CC_VERSION" \
        --package-id "${PACKAGE_IDS[$org]}" \
        --sequence "$CC_SEQUENCE" \
        --waitForEvent
}

chaincode_is_committed() {
    local committed
    committed="$(peer_exec registrar peer lifecycle chaincode querycommitted \
        --channelID "$CHANNEL_NAME" --name "$CC_NAME" --output json 2>/dev/null || true)"
    grep -Eq "\"sequence\"[[:space:]]*:[[:space:]]*$CC_SEQUENCE" <<<"$committed" && \
        grep -Fq "\"version\": \"$CC_VERSION\"" <<<"$committed"
}

commit_chaincode() {
    if chaincode_is_committed; then
        echo "[SKIP] $CC_NAME sequence $CC_SEQUENCE is already committed."
        return 0
    fi

    local readiness
    readiness="$(peer_exec registrar peer lifecycle chaincode checkcommitreadiness \
        --channelID "$CHANNEL_NAME" \
        --name "$CC_NAME" \
        --version "$CC_VERSION" \
        --sequence "$CC_SEQUENCE" \
        --output json)"
    for msp in RegistrarMSP FacultyMSP DepartmentMSP; do
        grep -Eq "\"$msp\"[[:space:]]*:[[:space:]]*true" <<<"$readiness" || {
            echo "ERROR: $msp has not approved the chaincode definition." >&2
            echo "$readiness" >&2
            return 1
        }
    done

    echo "[COMMIT] Committing $CC_NAME sequence $CC_SEQUENCE..."
    PEER_TLS_HOST_OVERRIDE="" peer_exec registrar peer lifecycle chaincode commit \
        --orderer "$ORDERER_ENDPOINT" \
        --ordererTLSHostnameOverride "$ORDERER_TLS_OVERRIDE" \
        --tls --cafile "$REMOTE_DIR/orderer-tls-ca.crt" \
        --channelID "$CHANNEL_NAME" \
        --name "$CC_NAME" \
        --version "$CC_VERSION" \
        --sequence "$CC_SEQUENCE" \
        --peerAddresses "${ORG_PEER_HOST[registrar]}:7051" \
        --tlsRootCertFiles "$REMOTE_DIR/registrar/peer-tls-ca.crt" \
        --peerAddresses "${ORG_PEER_HOST[faculty]}:7051" \
        --tlsRootCertFiles "$REMOTE_DIR/faculty/peer-tls-ca.crt" \
        --peerAddresses "${ORG_PEER_HOST[department]}:7051" \
        --tlsRootCertFiles "$REMOTE_DIR/department/peer-tls-ca.crt"
}

initialize_ledger() {
    sleep 5
    if peer_exec registrar peer chaincode query \
        --channelID "$CHANNEL_NAME" --name "$CC_NAME" \
        --ctor '{"Args":["ReadGrade","GENESIS-001"]}' >/dev/null 2>&1; then
        echo "[SKIP] Ledger genesis record already exists."
        return 0
    fi

    echo "[INIT] Creating the ledger genesis record..."
    PEER_TLS_HOST_OVERRIDE="" peer_exec registrar peer chaincode invoke \
        --orderer "$ORDERER_ENDPOINT" \
        --ordererTLSHostnameOverride "$ORDERER_TLS_OVERRIDE" \
        --tls --cafile "$REMOTE_DIR/orderer-tls-ca.crt" \
        --channelID "$CHANNEL_NAME" \
        --name "$CC_NAME" \
        --ctor '{"Args":["InitLedger"]}' \
        --peerAddresses "${ORG_PEER_HOST[registrar]}:7051" \
        --tlsRootCertFiles "$REMOTE_DIR/registrar/peer-tls-ca.crt" \
        --peerAddresses "${ORG_PEER_HOST[faculty]}:7051" \
        --tlsRootCertFiles "$REMOTE_DIR/faculty/peer-tls-ca.crt" \
        --peerAddresses "${ORG_PEER_HOST[department]}:7051" \
        --tlsRootCertFiles "$REMOTE_DIR/department/peer-tls-ca.crt" \
        --waitForEvent --waitForEventTimeout 60s
}

echo "======================================"
echo "Fabric Chaincode Bootstrap (CCaaS)"
echo "======================================"
echo "Channel: $CHANNEL_NAME"
echo "Chaincode: $CC_NAME $CC_VERSION (sequence $CC_SEQUENCE)"

CLI_POD="$(wait_for_cli)"
echo "CLI pod: $CLI_POD"

stage_cli_files
install_packages
sync_chaincode_ids

for org in "${ORGS[@]}"; do
    approve_for_org "$org"
done

commit_chaincode
initialize_ledger

echo "Fabric chaincode bootstrap completed successfully."
