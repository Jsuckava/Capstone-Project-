#!/bin/bash
# ============================================================
# BLOCKGO - FULL DEPLOYMENT (FABRIC CA BOOTSTRAP VERSION)
# ============================================================
set -e

# --- Configuration ---
CRYPTO_DIR="./crypto-config-final-v2"
ARTIFACTS_DIR="./channel-artifacts-final"
CHANNEL_NAME="registrar-channel"
CC_NAME="registrar"
CC_VERSION="1.0"
EXPECTED_FABRIC_VERSION="2.5.4"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

declare -a PIDS

cleanup_processes() {
    echo ""
    log_info "Shutting down background services..."
    for pid in "${PIDS[@]}"; do
        if ps -p $pid > /dev/null 2>&1; then kill $pid 2>/dev/null || true; fi
    done
    if [ -f .watchdog.pid ]; then
        kill -9 $(cat .watchdog.pid) 2>/dev/null || true
        rm -f .watchdog.pid
    fi
    pkill -9 -f nginx_failover_watchdog.sh 2>/dev/null || true
    docker compose -f docker-compose-main.yaml -f docker-compose-annex.yaml -f docker-compose-pubad.yaml down -v --remove-orphans 2>/dev/null || true
    docker rm -f -v couchdb_wallet couchdb_wallet_faculty couchdb_wallet_department blockgo-middleware blockgo-api-gateway blockgo-auth-service blockgo-fabric-identity-service blockgo-ledger-service blockgo-grade-upload-service blockgo-settings-service nginx-shield-main-failover nginx-shield-annex-failover nginx-shield-pubad-failover 2>/dev/null || true
    log_info "All processes stopped and volumes wiped."
}

trap cleanup_processes SIGINT SIGTERM ERR

wait_for_service() {
    local host=$1; local port=$2; local name=$3; local timeout=$4
    local start_time=$(date +%s)
    log_info "Waiting for $name ($host:$port)..."
    while ! nc -z -w 2 $host $port > /dev/null 2>&1 && ! bash -c "echo > /dev/tcp/$host/$port" > /dev/null 2>&1 && ! curl -s http://$host:$port > /dev/null 2>&1 && ! curl -s -k https://$host:$port > /dev/null 2>&1; do
        if [ $(($(date +%s) - start_time)) -ge $timeout ]; then 
            if [ "$port" == "7054" ]; then
                echo -e "\n--- CA REGISTRAR DOCKER LOGS ---"
                docker logs ca.registrar.capstone.com || true
                echo "--------------------------------"
            fi
            log_error "$name timeout on $host:$port!"
        fi
        sleep 2
    done
    log_info "$name is ready!"
}

wait_for_optional_service() {
    local host=$1; local port=$2; local name=$3; local timeout=$4
    local start_time=$(date +%s)
    log_info "Checking optional $name ($host:$port)..."
    while ! nc -z -w 2 $host $port > /dev/null 2>&1 && ! bash -c "echo > /dev/tcp/$host/$port" > /dev/null 2>&1; do
        if [ $(($(date +%s) - start_time)) -ge $timeout ]; then
            log_warn "$name is not reachable. Continuing because core services do not depend on nginx-shield."
            return 0
        fi
        sleep 2
    done
    log_info "$name is ready!"
}

wait_for_container_health() {
    local container_name=$1; local timeout=$2
    local start_time=$(date +%s)
    log_info "Waiting for $container_name to become healthy..."
    while true; do
        local status=$(docker inspect --format '{{.State.Health.Status}}' "$container_name" 2>/dev/null)
        if [ "$status" == "healthy" ]; then
            log_info "$container_name is healthy!"
            break
        fi
        if [ "$status" == "unhealthy" ]; then
                # Do not exit immediately; Postgres restarts itself during initialization which can temporarily flag it as unhealthy
                log_warn "$container_name reported as unhealthy. Waiting for recovery..."
        fi
        if [ $(($(date +%s) - start_time)) -ge $timeout ]; then
            log_error "Timeout waiting for $container_name to become healthy. Last status: ${status:-not_found}"
        fi
        sleep 5
    done
}

load_env_vars() {
    if [ -f .env ]; then
        log_info "Loading environment variables from .env file..."
        while IFS='=' read -r key value || [ -n "$key" ]; do
            # Skip empty lines and comments
            [[ -z "$key" || "$key" =~ ^# ]] && continue
            
            # Remove any leading/trailing quotes from the value
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"
            
            export "$key"="$value"
        done < .env
    fi
}
load_env_vars

# Critical Secret Validation
if [ -z "$JWT_SECRET" ] || [ -z "$INTERNAL_API_KEY" ] || [ -z "$POSTGRES_PASS" ]; then
    log_error "Critical environment variables (JWT_SECRET, INTERNAL_API_KEY, POSTGRES_PASS) are not set. Please define them in your .env file."
fi

spawn_couchdb_wallet() {
    log_info "Spawning standalone CouchDB Wallet container on port 5990..."
    # Prune existing wallet to ensure a clean state
    docker rm -f -v couchdb_wallet 2>/dev/null || true
    docker run -d --name couchdb_wallet \
        --network registrar-net \
        -e COUCHDB_USER="${COUCHDB_USER:-PLVADMIN}" \
        -e COUCHDB_PASSWORD="${COUCHDB_PASS:-PLVSYSTEM2026}" \
        -p 5990:5984 \
        couchdb:3.2.2
}

# ============================================================
# PHASE 1: INITIAL CLEANING & CA STARTUP
# ============================================================
log_info "Phase 1: Initializing CA infrastructure..."
log_warn "Wiping previous CA databases and crypto material..."

# Gracefully stop the orphaned watchdog if it's still running
if [ -f .watchdog.pid ]; then
    kill -9 $(cat .watchdog.pid) 2>/dev/null || true
    rm -f .watchdog.pid
fi
    pkill -9 -f nginx_failover_watchdog.sh 2>/dev/null || true

docker compose -f docker-compose-main.yaml -f docker-compose-annex.yaml -f docker-compose-pubad.yaml down -v --remove-orphans 2>/dev/null || true
docker rm -f -v couchdb_wallet couchdb_wallet_faculty couchdb_wallet_department blockgo-middleware blockgo-api-gateway blockgo-auth-service blockgo-fabric-identity-service blockgo-ledger-service blockgo-grade-upload-service blockgo-settings-service nginx-shield-main-failover nginx-shield-annex-failover nginx-shield-pubad-failover 2>/dev/null || true

# Force remove root-owned files created by containers to prevent CA container crashes
docker run --rm -v "$(pwd):/tmp/network" alpine sh -c "find /tmp/network/fabric-ca -type f ! -name '*.yaml' -delete && rm -rf /tmp/network/${CRYPTO_DIR} /tmp/network/${ARTIFACTS_DIR} /tmp/network/../middleware/wallet" 2>/dev/null || true

find ./fabric-ca -type f ! -name '*.yaml' -delete 2>/dev/null || true
rm -rf "$CRYPTO_DIR" "$ARTIFACTS_DIR" 2>/dev/null || true
rm -rf ../middleware/wallet 2>/dev/null || true
mkdir -p "$ARTIFACTS_DIR"

export PATH=$PATH:$(pwd)/bin
export FABRIC_CFG_PATH=$(pwd)

TMP_DOCKER_CFG=$(mktemp -d)
echo "{}" > "$TMP_DOCKER_CFG/config.json"
DOCKER_CONFIG=$TMP_DOCKER_CFG docker compose -f docker-compose-main.yaml -f docker-compose-annex.yaml -f docker-compose-pubad.yaml up -d ca.registrar.capstone.com ca.faculty.capstone.com ca.department.capstone.com cli
rm -rf "$TMP_DOCKER_CFG"

wait_for_service 127.0.0.1 7054 "Registrar CA" 120

# ============================================================
# PHASE 2: DYNAMIC ENROLLMENT
# ============================================================
log_info "Phase 2: Enrolling Identities via Fabric CA..."

enroll_org_identities() {
    local ORG=$1; local DOMAIN=$2; local PORT=$3; local MSP_ID=$4
    local ADMIN_PASS=${BOOTSTRAP_REGISTRAR_PASS:-adminpw}
    local ORG_DIR="$(pwd)/${CRYPTO_DIR}/peerOrganizations/${DOMAIN}"
    local TLS_CERT="$(pwd)/fabric-ca/${ORG}/tls-cert.pem" 
    local K8S_PEER_SERVICE=""
    local K8S_NAMESPACE=""

    case "$ORG" in
        registrar) K8S_PEER_SERVICE="peer-registrar"; K8S_NAMESPACE="plv-main-campus" ;;
        faculty) K8S_PEER_SERVICE="peer-faculty"; K8S_NAMESPACE="plv-annex-campus" ;;
        department) K8S_PEER_SERVICE="peer-department"; K8S_NAMESPACE="plv-pubad-campus" ;;
        *) log_error "Unknown organization for Kubernetes TLS SANs: $ORG" ;;
    esac
    
    log_info "Bootstrapping ${MSP_ID}..."
    mkdir -p "${ORG_DIR}/msp" "${ORG_DIR}/users/Admin@${DOMAIN}/msp" "${ORG_DIR}/peers/peer0.${DOMAIN}/msp" "${ORG_DIR}/peers/peer0.${DOMAIN}/tls" "${ORG_DIR}/peers/peer1.${DOMAIN}/msp" "${ORG_DIR}/peers/peer1.${DOMAIN}/tls"

    while [ ! -f "${TLS_CERT}" ]; do sleep 2; done

    fabric-ca-client enroll -u https://admin:${ADMIN_PASS}@localhost:${PORT} --caname ca-${ORG} --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"
    fabric-ca-client register --caname ca-${ORG} --id.name peer0 --id.secret peer0pw --id.type peer --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"
    fabric-ca-client enroll -u https://peer0:peer0pw@localhost:${PORT} --caname ca-${ORG} -M "${ORG_DIR}/peers/peer0.${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"

    fabric-ca-client enroll -u https://peer0:peer0pw@localhost:${PORT} --caname ca-${ORG} -M "${ORG_DIR}/peers/peer0.${DOMAIN}/tls" --enrollment.profile tls --csr.hosts "peer0.${DOMAIN},localhost,${K8S_PEER_SERVICE},${K8S_PEER_SERVICE}.${K8S_NAMESPACE}.svc.cluster.local" --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"

    cp "${ORG_DIR}/peers/peer0.${DOMAIN}/tls/signcerts/"* "${ORG_DIR}/peers/peer0.${DOMAIN}/tls/server.crt"
    cp "${ORG_DIR}/peers/peer0.${DOMAIN}/tls/keystore/"* "${ORG_DIR}/peers/peer0.${DOMAIN}/tls/server.key"
    cp "${ORG_DIR}/msp/cacerts/localhost-${PORT}-ca-${ORG}.pem" "${ORG_DIR}/peers/peer0.${DOMAIN}/tls/ca.crt"
    fabric-ca-client register --caname ca-${ORG} --id.name peer1 --id.secret peer1pw --id.type peer --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"
    fabric-ca-client enroll -u https://peer1:peer1pw@localhost:${PORT} --caname ca-${ORG} -M "${ORG_DIR}/peers/peer1.${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"
    fabric-ca-client enroll -u https://peer1:peer1pw@localhost:${PORT} --caname ca-${ORG} -M "${ORG_DIR}/peers/peer1.${DOMAIN}/tls" --enrollment.profile tls --csr.hosts "peer1.${DOMAIN},localhost,${K8S_PEER_SERVICE}-2,${K8S_PEER_SERVICE}-2.${K8S_NAMESPACE}.svc.cluster.local" --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"
    cp "${ORG_DIR}/peers/peer1.${DOMAIN}/tls/signcerts/"* "${ORG_DIR}/peers/peer1.${DOMAIN}/tls/server.crt"
    cp "${ORG_DIR}/peers/peer1.${DOMAIN}/tls/keystore/"* "${ORG_DIR}/peers/peer1.${DOMAIN}/tls/server.key"
    # The peer's TLS CA cert is the root cert of the CA that issued its TLS cert.
    cp "${ORG_DIR}/msp/cacerts/localhost-${PORT}-ca-${ORG}.pem" "${ORG_DIR}/peers/peer1.${DOMAIN}/tls/ca.crt"

    fabric-ca-client register --caname ca-${ORG} --id.name orgadmin --id.secret adminpw --id.type admin --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"
    fabric-ca-client enroll -u https://orgadmin:adminpw@localhost:${PORT} --caname ca-${ORG} -M "${ORG_DIR}/users/Admin@${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORG_DIR}"

    local CA_FILENAME="localhost-${PORT}-ca-${ORG}.pem"

    # Create tlscacerts for configtxgen and a compatibility link for Node.js Gateway
    mkdir -p "${ORG_DIR}/msp/tlscacerts" "${ORG_DIR}/tlsca"
    cp "${ORG_DIR}/msp/cacerts/${CA_FILENAME}" "${ORG_DIR}/msp/tlscacerts/tlsca.${DOMAIN}-cert.pem"
    cp "${ORG_DIR}/msp/cacerts/${CA_FILENAME}" "${ORG_DIR}/tlsca/tlsca.${DOMAIN}-cert.pem"

    cat <<EOF > "${ORG_DIR}/msp/config.yaml"
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: orderer
EOF
    cp "${ORG_DIR}/msp/config.yaml" "${ORG_DIR}/users/Admin@${DOMAIN}/msp/config.yaml"
    cp "${ORG_DIR}/msp/config.yaml" "${ORG_DIR}/peers/peer0.${DOMAIN}/msp/config.yaml"
    cp "${ORG_DIR}/msp/config.yaml" "${ORG_DIR}/peers/peer1.${DOMAIN}/msp/config.yaml"
}

enroll_orderer_identities() {
    local DOMAIN="capstone.com"
    local PORT=7054 # Using Registrar CA for Orderer
    local ADMIN_PASS=${BOOTSTRAP_REGISTRAR_PASS:-adminpw}
    local ORDERER_DIR="$(pwd)/${CRYPTO_DIR}/ordererOrganizations/${DOMAIN}"
    local TLS_CERT="$(pwd)/fabric-ca/registrar/tls-cert.pem"

    log_info "Bootstrapping Orderer (capstone.com)..."
    mkdir -p "${ORDERER_DIR}/msp"
    local orderer_name
    for orderer_name in orderer orderer2 orderer3 orderer4 orderer5 orderer6; do
        mkdir -p "${ORDERER_DIR}/orderers/${orderer_name}.${DOMAIN}/msp" "${ORDERER_DIR}/orderers/${orderer_name}.${DOMAIN}/tls"
    done

    while [ ! -f "${TLS_CERT}" ]; do log_warn "Waiting for Orderer's CA TLS cert..."; sleep 2; done

    fabric-ca-client enroll -u https://admin:${ADMIN_PASS}@localhost:${PORT} --caname ca-registrar --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    fabric-ca-client register --caname ca-registrar --id.name orderer --id.secret ordererpw --id.type orderer --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    
    # Enroll for MSP
    fabric-ca-client enroll -u https://orderer:ordererpw@localhost:${PORT} --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"

    # Enroll for TLS (This is what configtxgen needs!)
    fabric-ca-client enroll -u https://orderer:ordererpw@localhost:${PORT} --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/tls" --enrollment.profile tls --csr.hosts "orderer.capstone.com,localhost,orderer-1.plv-main-campus.svc.cluster.local" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"

    # Normalize TLS filenames for Fabric
    cp "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/tls/signcerts/"* "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/tls/server.crt"
    cp "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/tls/keystore/"* "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/tls/server.key"
    # The orderer's TLS CA cert is the root cert of the CA that issued its TLS cert.
    cp "${ORDERER_DIR}/msp/cacerts/localhost-7054-ca-registrar.pem" "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/tls/ca.crt"

    # Create admincerts directory for the orderer's MSP to satisfy admin requirement
    mkdir -p "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/msp/admincerts"
    cp "${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/users/Admin@registrar.capstone.com/msp/signcerts/cert.pem" \
       "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/msp/admincerts/cert.pem"
    
    # === ORDERER 2 (Annex) ===
    fabric-ca-client register --caname ca-registrar --id.name orderer2 --id.secret ordererpw --id.type orderer --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    fabric-ca-client enroll -u https://orderer2:ordererpw@localhost:${PORT} --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    fabric-ca-client enroll -u https://orderer2:ordererpw@localhost:${PORT} --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/tls" --enrollment.profile tls --csr.hosts "orderer2.capstone.com,localhost,orderer-2.plv-main-campus.svc.cluster.local" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    cp "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/tls/signcerts/"* "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/tls/server.crt"
    cp "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/tls/keystore/"* "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/tls/server.key"
    cp "${ORDERER_DIR}/msp/cacerts/localhost-7054-ca-registrar.pem" "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/tls/ca.crt"
    mkdir -p "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/msp/admincerts"
    cp "${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/users/Admin@registrar.capstone.com/msp/signcerts/cert.pem" "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/msp/admincerts/cert.pem"

    # === ORDERER 3 (Pubad) ===
    fabric-ca-client register --caname ca-registrar --id.name orderer3 --id.secret ordererpw --id.type orderer --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    fabric-ca-client enroll -u https://orderer3:ordererpw@localhost:${PORT} --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    fabric-ca-client enroll -u https://orderer3:ordererpw@localhost:${PORT} --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/tls" --enrollment.profile tls --csr.hosts "orderer3.capstone.com,localhost,orderer-3.plv-annex-campus.svc.cluster.local" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
    cp "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/tls/signcerts/"* "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/tls/server.crt"
    cp "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/tls/keystore/"* "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/tls/server.key"
    cp "${ORDERER_DIR}/msp/cacerts/localhost-7054-ca-registrar.pem" "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/tls/ca.crt"
    mkdir -p "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/msp/admincerts"
    cp "${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/users/Admin@registrar.capstone.com/msp/signcerts/cert.pem" "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/msp/admincerts/cert.pem"

    # Production orderers 4-6. The local configtx profile still uses only 1-3.
    local orderer_number
    local orderer_namespace
    for orderer_number in 4 5 6; do
        case "$orderer_number" in
            4) orderer_namespace="plv-annex-campus" ;;
            5|6) orderer_namespace="plv-pubad-campus" ;;
        esac
        fabric-ca-client register --caname ca-registrar --id.name "orderer${orderer_number}" --id.secret ordererpw --id.type orderer --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
        fabric-ca-client enroll -u "https://orderer${orderer_number}:ordererpw@localhost:${PORT}" --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/msp" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
        fabric-ca-client enroll -u "https://orderer${orderer_number}:ordererpw@localhost:${PORT}" --caname ca-registrar -M "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/tls" --enrollment.profile tls --csr.hosts "orderer${orderer_number}.capstone.com,localhost,orderer-${orderer_number},orderer-${orderer_number}.${orderer_namespace}.svc.cluster.local" --tls.certfiles "${TLS_CERT}" --home "${ORDERER_DIR}"
        cp "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/tls/signcerts/"* "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/tls/server.crt"
        cp "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/tls/keystore/"* "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/tls/server.key"
        cp "${ORDERER_DIR}/msp/cacerts/localhost-7054-ca-registrar.pem" "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/tls/ca.crt"
        mkdir -p "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/msp/admincerts"
        cp "${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/users/Admin@registrar.capstone.com/msp/signcerts/cert.pem" "${ORDERER_DIR}/orderers/orderer${orderer_number}.${DOMAIN}/msp/admincerts/cert.pem"
    done

    # Generate Orderer MSP config
    local CA_FILENAME="localhost-${PORT}-ca-registrar.pem"

    # Create tlscacerts for configtxgen and a compatibility link
    mkdir -p "${ORDERER_DIR}/msp/tlscacerts" "${ORDERER_DIR}/tlsca"
    cp "${ORDERER_DIR}/msp/cacerts/${CA_FILENAME}" "${ORDERER_DIR}/msp/tlscacerts/tlsca.${DOMAIN}-cert.pem"
    cp "${ORDERER_DIR}/msp/cacerts/${CA_FILENAME}" "${ORDERER_DIR}/tlsca/tlsca.${DOMAIN}-cert.pem"

    cat <<EOF > "${ORDERER_DIR}/msp/config.yaml"
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/${CA_FILENAME}
    OrganizationalUnitIdentifier: orderer
EOF
    cp "${ORDERER_DIR}/msp/config.yaml" "${ORDERER_DIR}/orderers/orderer.${DOMAIN}/msp/config.yaml"
    cp "${ORDERER_DIR}/msp/config.yaml" "${ORDERER_DIR}/orderers/orderer2.${DOMAIN}/msp/config.yaml"
    cp "${ORDERER_DIR}/msp/config.yaml" "${ORDERER_DIR}/orderers/orderer3.${DOMAIN}/msp/config.yaml"
    cp "${ORDERER_DIR}/msp/config.yaml" "${ORDERER_DIR}/orderers/orderer4.${DOMAIN}/msp/config.yaml"
    cp "${ORDERER_DIR}/msp/config.yaml" "${ORDERER_DIR}/orderers/orderer5.${DOMAIN}/msp/config.yaml"
    cp "${ORDERER_DIR}/msp/config.yaml" "${ORDERER_DIR}/orderers/orderer6.${DOMAIN}/msp/config.yaml"
}

# Run all enrollments
enroll_org_identities "registrar" "registrar.capstone.com" 7054 "RegistrarMSP"
enroll_org_identities "faculty" "faculty.capstone.com" 8054 "FacultyMSP"
enroll_org_identities "department" "department.capstone.com" 9054 "DepartmentMSP"
enroll_orderer_identities

log_info "Creating dedicated TLS identity for Chaincode service..."
# Register a new identity for the chaincode service itself
fabric-ca-client register --caname ca-registrar --id.name chaincode --id.secret cc_pw --id.type client --tls.certfiles "$(pwd)/fabric-ca/registrar/tls-cert.pem" --home "$(pwd)/${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com"
# Enroll to get its TLS certificate
fabric-ca-client enroll -u https://chaincode:cc_pw@localhost:7054 --caname ca-registrar -M "$(pwd)/${CRYPTO_DIR}/chaincode-tls" --enrollment.profile tls --csr.hosts "registrar-chaincode,faculty-chaincode,department-chaincode,localhost" --tls.certfiles "$(pwd)/fabric-ca/registrar/tls-cert.pem" --home "$(pwd)/${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com"

# Normalize the filenames for the chaincode container's environment variables
mkdir -p "$(pwd)/${CRYPTO_DIR}/chaincode-tls/keystore"
mv "$(pwd)/${CRYPTO_DIR}/chaincode-tls/keystore/"* "$(pwd)/${CRYPTO_DIR}/chaincode-tls/keystore/server.key"
mkdir -p "$(pwd)/${CRYPTO_DIR}/chaincode-tls/signcerts"
mv "$(pwd)/${CRYPTO_DIR}/chaincode-tls/signcerts/"* "$(pwd)/${CRYPTO_DIR}/chaincode-tls/signcerts/server.crt"

log_info "Creating bundled TLS CA cert for Chaincode service to trust all peers..."
# Create a bundle of all organization's TLS CAs for the chaincode to trust
mkdir -p "$(pwd)/${CRYPTO_DIR}/chaincode-tls/ca-bundle"
{
    cat "$(pwd)/${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/tlsca/tlsca.registrar.capstone.com-cert.pem"
    echo ""
    cat "$(pwd)/${CRYPTO_DIR}/peerOrganizations/faculty.capstone.com/tlsca/tlsca.faculty.capstone.com-cert.pem"
    echo ""
    cat "$(pwd)/${CRYPTO_DIR}/peerOrganizations/department.capstone.com/tlsca/tlsca.department.capstone.com-cert.pem"
    echo ""
} > "$(pwd)/${CRYPTO_DIR}/chaincode-tls/ca-bundle/ca-bundle.pem"

log_info "Identities enrolled. Normalizing private keys..."
find "$CRYPTO_DIR" -type f -name "*_sk" -execdir cp -n {} priv_sk \; 2>/dev/null || true
# ============================================================
# PHASE 2.5: CREATE EXTERNAL BUILDER SCRIPTS
# ============================================================
log_info "Phase 2.5: Generating CCaaS External Builder scripts..."
mkdir -p ./builders/ccaas/bin

cat << 'EOF' | tr -d '\r' > ./builders/ccaas/bin/detect
#!/bin/sh
set -eu
exit 0
EOF

cat << 'EOF' | tr -d '\r' > ./builders/ccaas/bin/build
#!/bin/sh
set -eu
tar xfz "$1/code.tar.gz" -C "$3"
exit 0
EOF

cat << 'EOF' | tr -d '\r' > ./builders/ccaas/bin/release
#!/bin/sh
set -eu
mkdir -p "$2/chaincode/server"
cp "$1/connection.json" "$2/chaincode/server/connection.json"
exit 0
EOF

chmod -R +x ./builders/ccaas/bin
# ============================================================
# PHASE 3: FRONTEND BUILD & ARTIFACTS
# ============================================================
log_info "Phase 3: Building frontend application..."
(cd ../frontend && \
 rm -rf build && npm install && npm install react-router-dom @microsoft/signalr && \
 npm install -D tailwindcss@3 postcss autoprefixer && \
 npx tailwindcss init -p && \
 echo "module.exports = { content: ['./src/**/*.{js,jsx,ts,tsx}'], theme: { extend: {} }, plugins: [] };" > tailwind.config.js && \
 if [ -f src/index.css ] && ! grep -q "@tailwind" src/index.css; then echo -e "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n$(cat src/index.css)" > src/index.css; \
 elif [ ! -f src/index.css ]; then echo -e "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n" > src/index.css; fi && \
 DISABLE_ESLINT_PLUGIN=true npm run build)

if ! grep -q "orderer3.capstone.com" config/configtx.yaml; then
    log_error "Your configtx.yaml is missing the 3-node Raft cluster! Please update it to include orderer, orderer2, and orderer3."
fi

log_info "Generating Channel Artifacts..."
export FABRIC_CFG_PATH="$(pwd)/config"
configtxgen -profile UniversityGenesis -channelID system-channel -outputBlock "./${ARTIFACTS_DIR}/orderer.genesis.block"

configtxgen -profile RegistrarChannel -outputBlock "./${ARTIFACTS_DIR}/${CHANNEL_NAME}.block" -channelID $CHANNEL_NAME

log_info "Shutting down local Certificate Authorities..."
docker compose -f docker-compose-main.yaml -f docker-compose-annex.yaml -f docker-compose-pubad.yaml down -v --remove-orphans 2>/dev/null || true

log_info "============================================================"
log_info "CLOUD CRYPTO PREPARATION COMPLETE!"
log_info "All certificates and Genesis blocks have been safely generated."
log_info "You can now run: ./k8s/deploy-k8s.sh apply"
log_info "============================================================"
