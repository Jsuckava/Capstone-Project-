#!/bin/bash
set -euo pipefail

# ============================================================
# PLV BLOCKGO - Kubernetes Crypto Secret Generator
# ============================================================

CRYPTO_DIR="./crypto-config-final-v2"
CA_DIR="./fabric-ca"
PROFILE="${K8S_PROFILE:-local}"
TLS_MIN_VALIDITY_SECONDS="${TLS_MIN_VALIDITY_SECONDS:-2592000}"
ARTIFACTS_DIR="./channel-artifacts-final"

if [[ "$PROFILE" == "production" ]]; then
    ARTIFACTS_DIR="./channel-artifacts-k8s"
fi

NAMESPACE_FABRIC="plv-fabric"
NAMESPACE_MAIN="plv-main-campus"
NAMESPACE_ANNEX="plv-annex-campus"
NAMESPACE_PUBAD="plv-pubad-campus"


# ============================================================
# Helpers
# ============================================================

require_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file does not exist:"
        echo "  $file"
        return 1
    fi
}


require_directory() {
    local directory="$1"

    if [[ ! -d "$directory" ]]; then
        echo "ERROR: Required directory does not exist:"
        echo "  $directory"
        return 1
    fi
}


find_first_file() {
    local directory="$1"
    local pattern="${2:-*}"

    if [[ ! -d "$directory" ]]; then
        return 1
    fi

    find "$directory" \
        -maxdepth 1 \
        -type f \
        -name "$pattern" \
        -print \
        -quit 2>/dev/null || true
}


certificate_public_key_hash() {
    local cert_file="$1"

    openssl x509 \
        -in "$cert_file" \
        -pubkey \
        -noout 2>/dev/null \
    | openssl pkey \
        -pubin \
        -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print $1}'
}


private_key_public_hash() {
    local key_file="$1"

    openssl pkey \
        -in "$key_file" \
        -pubout \
        -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print $1}'
}


find_matching_private_key() {
    local cert_file="$1"
    local keystore_dir="$2"

    if [[ ! -f "$cert_file" ]]; then
        echo "ERROR: Certificate does not exist:" >&2
        echo "  $cert_file" >&2
        return 1
    fi

    if [[ ! -d "$keystore_dir" ]]; then
        echo "ERROR: Keystore directory does not exist:" >&2
        echo "  $keystore_dir" >&2
        return 1
    fi

    local cert_hash=""

    cert_hash="$(
        certificate_public_key_hash "$cert_file" 2>/dev/null || true
    )"

    if [[ -z "$cert_hash" ]]; then
        echo "ERROR: Unable to extract public key from certificate:" >&2
        echo "  $cert_file" >&2
        return 1
    fi

    local key=""
    local key_hash=""

    while IFS= read -r -d '' key; do

        key_hash="$(
            private_key_public_hash "$key" 2>/dev/null || true
        )"

        if [[ -n "$key_hash" && "$key_hash" == "$cert_hash" ]]; then
            printf '%s\n' "$key"
            return 0
        fi

    done < <(
        find "$keystore_dir" \
            -maxdepth 1 \
            -type f \
            -print0 2>/dev/null || true
    )

    echo "ERROR: No private key matches certificate:" >&2
    echo "  Certificate: $cert_file" >&2
    echo "  Keystore:    $keystore_dir" >&2

    echo "Available keystore files:" >&2

    find "$keystore_dir" \
        -maxdepth 1 \
        -type f \
        -printf '  %f\n' 2>/dev/null >&2 || true

    return 1
}


validate_key_matches_certificate() {
    local cert_file="$1"
    local key_file="$2"

    local cert_hash=""
    local key_hash=""

    cert_hash="$(
        certificate_public_key_hash "$cert_file" 2>/dev/null || true
    )"

    key_hash="$(
        private_key_public_hash "$key_file" 2>/dev/null || true
    )"

    if [[ -z "$cert_hash" || -z "$key_hash" ]]; then
        return 1
    fi

    [[ "$cert_hash" == "$key_hash" ]]
}


validate_tls_certificate() {
    local cert_file="$1"
    local ca_file="$2"
    local dns_name="$3"

    if ! openssl x509 -in "$cert_file" -noout -checkend "$TLS_MIN_VALIDITY_SECONDS" >/dev/null; then
        echo "ERROR: TLS certificate is expired or has less than ${TLS_MIN_VALIDITY_SECONDS} seconds remaining:"
        echo "  $cert_file"
        return 1
    fi

    if ! openssl verify -CAfile "$ca_file" "$cert_file" >/dev/null; then
        echo "ERROR: TLS certificate does not verify against its configured CA:"
        echo "  Certificate: $cert_file"
        echo "  CA:          $ca_file"
        return 1
    fi

    if [[ "$PROFILE" == "production" ]] &&
       ! openssl x509 -in "$cert_file" -noout -checkhost "$dns_name" >/dev/null; then
        echo "ERROR: Production TLS certificate is missing Kubernetes DNS SAN:"
        echo "  Certificate: $cert_file"
        echo "  Required SAN: $dns_name"
        echo "Regenerate crypto with ./full_deploy.sh before deploying to GKE."
        return 1
    fi
}


apply_secret() {
    local namespace="$1"
    shift

    kubectl create secret generic "$@" \
        -n "$namespace" \
        --dry-run=client \
        -o yaml \
    | kubectl apply -f -
}


# ============================================================
# CA Secrets
# ============================================================

create_ca_secret() {
    local org="$1"
    local ns="$2"

    local secret_name="ca-${org}-identity"
    local src_dir="${CA_DIR}/${org}"
    local service_dns=""
    case "$org" in
        registrar) service_dns="ca-registrar.${NAMESPACE_MAIN}.svc.cluster.local" ;;
        faculty) service_dns="ca-faculty.${NAMESPACE_ANNEX}.svc.cluster.local" ;;
        department) service_dns="ca-department.${NAMESPACE_PUBAD}.svc.cluster.local" ;;
    esac

    echo ""
    echo "======================================"
    echo "Creating CA identity"
    echo "======================================"
    echo "Organization: $org"
    echo "Namespace:    $ns"
    echo "Secret:       $secret_name"

    require_directory "$src_dir"
    require_directory "${src_dir}/msp/keystore"

    require_file "${src_dir}/ca-cert.pem"
    require_file "${src_dir}/tls-cert.pem"
    validate_tls_certificate "${src_dir}/tls-cert.pem" "${src_dir}/ca-cert.pem" "$service_dns"

    local ca_key=""
    local tls_key=""

    if ! ca_key="$(
        find_matching_private_key \
            "${src_dir}/ca-cert.pem" \
            "${src_dir}/msp/keystore"
    )"; then

        echo "ERROR: Could not locate private key matching CA certificate."
        return 1
    fi

    if ! tls_key="$(
        find_matching_private_key \
            "${src_dir}/tls-cert.pem" \
            "${src_dir}/msp/keystore"
    )"; then

        echo "WARNING: Could not locate separate TLS private key."

        # Some Fabric CA layouts use the same identity key.
        if validate_key_matches_certificate \
            "${src_dir}/tls-cert.pem" \
            "$ca_key"
        then
            tls_key="$ca_key"
        else
            echo "ERROR: No valid TLS key found for ${org} CA."
            return 1
        fi
    fi

    apply_secret "$ns" "$secret_name" \
        --from-file="ca-cert.pem=${src_dir}/ca-cert.pem" \
        --from-file="tls-cert.pem=${src_dir}/tls-cert.pem" \
        --from-file="ca-key.pem=${ca_key}" \
        --from-file="tls-key.pem=${tls_key}"

    echo "SUCCESS: $ns/$secret_name"
}


# ============================================================
# Middleware CA roots
# ============================================================

create_middleware_ca_roots_secret() {
    local secret_name="fabric-ca-roots"

    echo ""
    echo "Creating $NAMESPACE_FABRIC/$secret_name"

    require_file "./fabric-ca/registrar/ca-cert.pem"
    require_file "./fabric-ca/registrar/tls-cert.pem"

    require_file "./fabric-ca/faculty/ca-cert.pem"
    require_file "./fabric-ca/faculty/tls-cert.pem"

    require_file "./fabric-ca/department/ca-cert.pem"
    require_file "./fabric-ca/department/tls-cert.pem"

    apply_secret "$NAMESPACE_FABRIC" "$secret_name" \
        --from-file="registrar-ca-cert.pem=./fabric-ca/registrar/ca-cert.pem" \
        --from-file="registrar-tls-cert.pem=./fabric-ca/registrar/tls-cert.pem" \
        --from-file="faculty-ca-cert.pem=./fabric-ca/faculty/ca-cert.pem" \
        --from-file="faculty-tls-cert.pem=./fabric-ca/faculty/tls-cert.pem" \
        --from-file="department-ca-cert.pem=./fabric-ca/department/ca-cert.pem" \
        --from-file="department-tls-cert.pem=./fabric-ca/department/tls-cert.pem"

    echo "SUCCESS: $NAMESPACE_FABRIC/$secret_name"
}


# ============================================================
# Middleware Gateway TLS roots
# ============================================================

create_middleware_gateway_tls_roots_secret() {
    local secret_name="fabric-gateway-tls-roots"

    local orderer_ca="${CRYPTO_DIR}/ordererOrganizations/capstone.com/orderers/orderer.capstone.com/tls/ca.crt"

    local registrar_ca="${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/peers/peer0.registrar.capstone.com/tls/ca.crt"

    local faculty_ca="${CRYPTO_DIR}/peerOrganizations/faculty.capstone.com/peers/peer0.faculty.capstone.com/tls/ca.crt"

    local department_ca="${CRYPTO_DIR}/peerOrganizations/department.capstone.com/peers/peer0.department.capstone.com/tls/ca.crt"

    echo ""
    echo "Creating $NAMESPACE_FABRIC/$secret_name"

    require_file "$orderer_ca"
    require_file "$registrar_ca"
    require_file "$faculty_ca"
    require_file "$department_ca"

    apply_secret "$NAMESPACE_FABRIC" "$secret_name" \
        --from-file="orderer-ca.crt=${orderer_ca}" \
        --from-file="registrar-peer-ca.crt=${registrar_ca}" \
        --from-file="faculty-peer-ca.crt=${faculty_ca}" \
        --from-file="department-peer-ca.crt=${department_ca}"

    echo "SUCCESS: $NAMESPACE_FABRIC/$secret_name"
}


# ============================================================
# Node crypto Secrets
# ============================================================

create_node_secret() {
    local type="$1"
    local org="$2"
    local domain="$3"
    local ns="$4"
    local name="$5"

    local secret_name="${type}-${org}-crypto"
    local path="${CRYPTO_DIR}/${type}Organizations/${domain}/${type}s/${name}"

    echo ""
    echo "======================================"
    echo "Creating crypto secret"
    echo "======================================"
    echo "Type:       $type"
    echo "Node:       $name"
    echo "Namespace:  $ns"
    echo "Secret:     $secret_name"
    echo "Path:       $path"

    # --------------------------------------------------------
    # Base directories
    # --------------------------------------------------------

    require_directory "$path"
    require_directory "${path}/msp"
    require_directory "${path}/msp/signcerts"
    require_directory "${path}/msp/keystore"
    require_directory "${path}/msp/cacerts"
    require_directory "${path}/tls"

    # --------------------------------------------------------
    # MSP signing certificate
    # --------------------------------------------------------

    local signcert=""

    signcert="$(
        find_first_file \
            "${path}/msp/signcerts" \
            "*.pem" || true
    )"

    if [[ -z "$signcert" ]]; then
        echo "ERROR: Signing certificate not found:"
        echo "  ${path}/msp/signcerts"
        return 1
    fi

    echo "Signing certificate:"
    echo "  $signcert"

    # --------------------------------------------------------
    # Matching MSP private key
    # --------------------------------------------------------

    local keystore=""

    if ! keystore="$(
        find_matching_private_key \
            "$signcert" \
            "${path}/msp/keystore"
    )"; then

        echo ""
        echo "ERROR: Matching MSP private key not found."
        echo "Node:"
        echo "  $name"
        echo "Certificate:"
        echo "  $signcert"
        echo "Keystore:"
        echo "  ${path}/msp/keystore"
        echo ""
        return 1
    fi

    if [[ -z "$keystore" || ! -f "$keystore" ]]; then
        echo "ERROR: Invalid keystore result:"
        echo "  $keystore"
        return 1
    fi

    echo "Matching MSP private key:"
    echo "  $keystore"

    # --------------------------------------------------------
    # Verify private key
    # --------------------------------------------------------

    if ! openssl pkey \
        -in "$keystore" \
        -check \
        -noout >/dev/null 2>&1
    then
        echo "ERROR: Invalid private key:"
        echo "  $keystore"
        return 1
    fi

    if ! validate_key_matches_certificate \
        "$signcert" \
        "$keystore"
    then
        echo "ERROR: MSP certificate and private key DO NOT MATCH."
        echo "Certificate:"
        echo "  $signcert"
        echo "Private key:"
        echo "  $keystore"
        return 1
    fi

    echo "MSP signing identity: VALID"

    # --------------------------------------------------------
    # MSP CA
    # --------------------------------------------------------

    local cacert=""

    cacert="$(
        find_first_file \
            "${path}/msp/cacerts" \
            "*.pem" || true
    )"

    if [[ -z "$cacert" ]]; then
        echo "ERROR: MSP CA certificate not found:"
        echo "  ${path}/msp/cacerts"
        return 1
    fi

    echo "MSP CA:"
    echo "  $cacert"

    # --------------------------------------------------------
    # TLS files
    # --------------------------------------------------------

    local tls_cert="${path}/tls/server.crt"
    local tls_key="${path}/tls/server.key"
    local tls_ca="${path}/tls/ca.crt"

    require_file "$tls_cert"
    require_file "$tls_key"
    require_file "$tls_ca"

    if ! openssl pkey \
        -in "$tls_key" \
        -check \
        -noout >/dev/null 2>&1
    then
        echo "ERROR: Invalid TLS private key:"
        echo "  $tls_key"
        return 1
    fi

    if ! validate_key_matches_certificate \
        "$tls_cert" \
        "$tls_key"
    then
        echo "ERROR: TLS certificate and TLS private key do not match:"
        echo "  Certificate: $tls_cert"
        echo "  Key:         $tls_key"
        return 1
    fi

    local service_name=""
    if [[ "$type" == "orderer" ]]; then
        service_name="orderer-${org}"
    else
        service_name="peer-${org}"
    fi
    validate_tls_certificate "$tls_cert" "$tls_ca" "${service_name}.${ns}.svc.cluster.local"

    echo "TLS identity: VALID"

    # --------------------------------------------------------
    # Admin certificate
    # --------------------------------------------------------

    local admincert=""

    if [[ "$type" == "orderer" ]]; then

        # First try the Orderer organization Admin.
        admincert="$(
            find_first_file \
                "${CRYPTO_DIR}/ordererOrganizations/${domain}/users/Admin@${domain}/msp/signcerts" \
                "*.pem" || true
        )"

        # Compatibility fallback for your existing crypto layout.
        if [[ -z "$admincert" ]]; then
            admincert="$(
                find_first_file \
                    "${CRYPTO_DIR}/peerOrganizations/registrar.capstone.com/users/Admin@registrar.capstone.com/msp/signcerts" \
                    "*.pem" || true
            )"
        fi

    else

        admincert="$(
            find_first_file \
                "${CRYPTO_DIR}/${type}Organizations/${domain}/users/Admin@${domain}/msp/signcerts" \
                "*.pem" || true
        )"

    fi

    if [[ -z "$admincert" || ! -f "$admincert" ]]; then
        echo "ERROR: Admin certificate not found for:"
        echo "  $name"
        return 1
    fi

    echo "Admin certificate:"
    echo "  $admincert"

    # --------------------------------------------------------
    # Create/update Kubernetes Secret
    # --------------------------------------------------------

    apply_secret "$ns" "$secret_name" \
        --from-file="server.crt=${tls_cert}" \
        --from-file="server.key=${tls_key}" \
        --from-file="ca.crt=${tls_ca}" \
        --from-file="msp-cert.pem=${signcert}" \
        --from-file="msp-key.pem=${keystore}" \
        --from-file="msp-ca.pem=${cacert}" \
        --from-file="admin-cert.pem=${admincert}"

    # --------------------------------------------------------
    # Verify resulting Kubernetes Secret
    # --------------------------------------------------------

    echo "Verifying Kubernetes Secret..."

    local secret_key_size=""

    secret_key_size="$(
        kubectl get secret "$secret_name" \
            -n "$ns" \
            -o go-template='{{index .data "msp-key.pem"}}' \
        | base64 -d \
        | wc -c
    )"

    secret_key_size="$(echo "$secret_key_size" | tr -d '[:space:]')"

    if [[ -z "$secret_key_size" || "$secret_key_size" -le 0 ]]; then
        echo "ERROR: Secret contains empty msp-key.pem:"
        echo "  $ns/$secret_name"
        return 1
    fi

    echo "SUCCESS: $ns/$secret_name"
    echo "MSP key size: ${secret_key_size} bytes"
}


# ============================================================
# Admin crypto Secrets
# ============================================================

create_admin_secret() {
    local org="$1"
    local domain="$2"
    local ns="$3"

    local secret_name="admin-${org}-crypto"
    local path="${CRYPTO_DIR}/peerOrganizations/${domain}/users/Admin@${domain}"

    echo ""
    echo "======================================"
    echo "Creating admin crypto secret"
    echo "======================================"
    echo "Organization: $org"
    echo "Namespace:    $ns"
    echo "Secret:       $secret_name"

    require_directory "$path"
    require_directory "${path}/msp/signcerts"
    require_directory "${path}/msp/keystore"
    require_directory "${path}/msp/cacerts"

    local signcert=""

    signcert="$(
        find_first_file \
            "${path}/msp/signcerts" \
            "*.pem" || true
    )"

    if [[ -z "$signcert" ]]; then
        echo "ERROR: Admin signing certificate missing:"
        echo "  ${path}/msp/signcerts"
        return 1
    fi

    local keystore=""

    if ! keystore="$(
        find_matching_private_key \
            "$signcert" \
            "${path}/msp/keystore"
    )"; then
        echo "ERROR: Admin private key does not match certificate."
        echo "  $path"
        return 1
    fi

    local cacert=""

    cacert="$(
        find_first_file \
            "${path}/msp/cacerts" \
            "*.pem" || true
    )"

    if [[ -z "$cacert" ]]; then
        echo "ERROR: Admin MSP CA certificate missing:"
        echo "  ${path}/msp/cacerts"
        return 1
    fi

    if ! validate_key_matches_certificate \
        "$signcert" \
        "$keystore"
    then
        echo "ERROR: Admin signing certificate and private key do not match."
        return 1
    fi

    apply_secret "$ns" "$secret_name" \
        --from-file="msp-cert.pem=${signcert}" \
        --from-file="msp-key.pem=${keystore}" \
        --from-file="msp-ca.pem=${cacert}" \
        --from-file="admin-cert.pem=${signcert}"

    echo "SUCCESS: $ns/$secret_name"
}


# ============================================================
# Chaincode TLS Secrets
# ============================================================

create_chaincode_tls_secret() {
    local org="$1"
    local ns="$2"

    local secret_name="chaincode-${org}-tls"
    local path="${CRYPTO_DIR}/chaincode-tls"

    echo ""
    echo "Creating chaincode TLS secret:"
    echo "  $ns/$secret_name"

    require_file "${path}/signcerts/server.crt"
    require_file "${path}/keystore/server.key"
    require_file "${path}/ca-bundle/ca-bundle.pem"

    if ! validate_key_matches_certificate \
        "${path}/signcerts/server.crt" \
        "${path}/keystore/server.key"
    then
        echo "ERROR: Chaincode TLS certificate and key do not match."
        return 1
    fi

    validate_tls_certificate \
        "${path}/signcerts/server.crt" \
        "${path}/ca-bundle/ca-bundle.pem" \
        "${org}-chaincode"

    apply_secret "$ns" "$secret_name" \
        --from-file="server.crt=${path}/signcerts/server.crt" \
        --from-file="server.key=${path}/keystore/server.key" \
        --from-file="ca-bundle.pem=${path}/ca-bundle/ca-bundle.pem"

    echo "SUCCESS: $ns/$secret_name"
}


# ============================================================
# Fabric artifacts
# ============================================================

create_artifact_secret() {
    local namespace="$1"
    local secret_name="fabric-artifacts"

    local genesis="${ARTIFACTS_DIR}/orderer.genesis.block"
    local channel="${ARTIFACTS_DIR}/registrar-channel.block"

    echo ""
    echo "Creating artifact secret:"
    echo "  $namespace/$secret_name"

    require_file "$genesis"
    require_file "$channel"

    apply_secret "$namespace" "$secret_name" \
        --from-file="orderer.genesis.block=${genesis}" \
        --from-file="registrar-channel.block=${channel}"

    echo "SUCCESS: $namespace/$secret_name"
}


# ============================================================
# MAIN
# ============================================================

echo ""
echo "======================================"
echo "PLV BLOCKGO Crypto Secret Generator"
echo "======================================"

require_directory "$CRYPTO_DIR"
require_directory "$CA_DIR"


# ------------------------------------------------------------
# 1. Fabric CAs
# ------------------------------------------------------------

echo ""
echo "======================================"
echo "1. Fabric CA Secrets"
echo "======================================"

create_ca_secret \
    "registrar" \
    "${NAMESPACE_MAIN}"

create_ca_secret \
    "faculty" \
    "${NAMESPACE_ANNEX}"

create_ca_secret \
    "department" \
    "${NAMESPACE_PUBAD}"

create_middleware_ca_roots_secret

create_middleware_gateway_tls_roots_secret


# ------------------------------------------------------------
# 2. Orderers
# ------------------------------------------------------------

echo ""
echo "======================================"
echo "2. Orderer Crypto Secrets"
echo "======================================"

create_node_secret \
    "orderer" \
    "1" \
    "capstone.com" \
    "${NAMESPACE_MAIN}" \
    "orderer.capstone.com"

create_node_secret \
    "orderer" \
    "2" \
    "capstone.com" \
    "${NAMESPACE_MAIN}" \
    "orderer2.capstone.com"

create_node_secret \
    "orderer" \
    "3" \
    "capstone.com" \
    "${NAMESPACE_ANNEX}" \
    "orderer3.capstone.com"

if [[ "$PROFILE" == "production" ]]; then
    create_node_secret "orderer" "4" "capstone.com" "${NAMESPACE_ANNEX}" "orderer4.capstone.com"
    create_node_secret "orderer" "5" "capstone.com" "${NAMESPACE_PUBAD}" "orderer5.capstone.com"
    create_node_secret "orderer" "6" "capstone.com" "${NAMESPACE_PUBAD}" "orderer6.capstone.com"
fi


# ------------------------------------------------------------
# 3. Peers
# ------------------------------------------------------------

echo ""
echo "======================================"
echo "3. Peer Crypto Secrets"
echo "======================================"

create_node_secret \
    "peer" \
    "registrar" \
    "registrar.capstone.com" \
    "${NAMESPACE_MAIN}" \
    "peer0.registrar.capstone.com"

create_node_secret \
    "peer" \
    "registrar-2" \
    "registrar.capstone.com" \
    "${NAMESPACE_MAIN}" \
    "peer1.registrar.capstone.com"

create_node_secret \
    "peer" \
    "faculty" \
    "faculty.capstone.com" \
    "${NAMESPACE_ANNEX}" \
    "peer0.faculty.capstone.com"

create_node_secret \
    "peer" \
    "faculty-2" \
    "faculty.capstone.com" \
    "${NAMESPACE_ANNEX}" \
    "peer1.faculty.capstone.com"

create_node_secret \
    "peer" \
    "department" \
    "department.capstone.com" \
    "${NAMESPACE_PUBAD}" \
    "peer0.department.capstone.com"

create_node_secret \
    "peer" \
    "department-2" \
    "department.capstone.com" \
    "${NAMESPACE_PUBAD}" \
    "peer1.department.capstone.com"


# ------------------------------------------------------------
# 4. Admin identities
# ------------------------------------------------------------

echo ""
echo "======================================"
echo "4. Admin Crypto Secrets"
echo "======================================"

create_admin_secret \
    "registrar" \
    "registrar.capstone.com" \
    "${NAMESPACE_MAIN}"

create_admin_secret \
    "faculty" \
    "faculty.capstone.com" \
    "${NAMESPACE_ANNEX}"

create_admin_secret \
    "department" \
    "department.capstone.com" \
    "${NAMESPACE_PUBAD}"


# Middleware also needs admin identities.

create_admin_secret \
    "registrar" \
    "registrar.capstone.com" \
    "${NAMESPACE_FABRIC}"

create_admin_secret \
    "faculty" \
    "faculty.capstone.com" \
    "${NAMESPACE_FABRIC}"

create_admin_secret \
    "department" \
    "department.capstone.com" \
    "${NAMESPACE_FABRIC}"


# ------------------------------------------------------------
# 5. Chaincode TLS
# ------------------------------------------------------------

echo ""
echo "======================================"
echo "5. Chaincode TLS Secrets"
echo "======================================"

create_chaincode_tls_secret \
    "registrar" \
    "${NAMESPACE_MAIN}"

create_chaincode_tls_secret \
    "faculty" \
    "${NAMESPACE_ANNEX}"

create_chaincode_tls_secret \
    "department" \
    "${NAMESPACE_PUBAD}"


# ------------------------------------------------------------
# 6. Fabric artifacts
# ------------------------------------------------------------

echo ""
echo "======================================"
echo "6. Fabric Artifact Secrets"
echo "======================================"

create_artifact_secret "${NAMESPACE_MAIN}"
create_artifact_secret "${NAMESPACE_ANNEX}"
create_artifact_secret "${NAMESPACE_PUBAD}"


echo ""
echo "======================================"
echo "ALL CRYPTO SECRETS CREATED"
echo "======================================"
echo ""
echo "Orderers:"
echo "  ${NAMESPACE_MAIN}/orderer-1-crypto"
echo "  ${NAMESPACE_MAIN}/orderer-2-crypto"
echo "  ${NAMESPACE_ANNEX}/orderer-3-crypto"
if [[ "$PROFILE" == "production" ]]; then
    echo "  ${NAMESPACE_ANNEX}/orderer-4-crypto"
    echo "  ${NAMESPACE_PUBAD}/orderer-5-crypto"
    echo "  ${NAMESPACE_PUBAD}/orderer-6-crypto"
fi
echo ""
echo "Crypto validation completed successfully."
echo ""
