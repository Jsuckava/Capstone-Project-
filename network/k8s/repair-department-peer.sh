#!/bin/bash
set -euo pipefail

NS="plv-pubad-campus"
PEER="peer-department"
PVC="peer-department-pvc"
CRYPTO_SECRET="peer-department-crypto"
REPAIR_POD="peer-department-repair"

echo "======================================"
echo "Department Peer Database Repair"
echo "======================================"

echo
echo "===== STOP DEPARTMENT PEER ====="

kubectl scale deployment/"$PEER" \
  -n "$NS" \
  --replicas=0

kubectl wait \
  --for=delete pod \
  -l app="$PEER" \
  -n "$NS" \
  --timeout=90s || true


echo
echo "===== DELETE OLD REPAIR POD ====="

kubectl delete pod "$REPAIR_POD" \
  -n "$NS" \
  --ignore-not-found \
  --wait=true


echo
echo "===== CREATE REPAIR POD ====="

cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${REPAIR_POD}
  namespace: ${NS}

spec:
  restartPolicy: Never

  containers:
  - name: repair
    image: hyperledger/fabric-peer:2.5.4
    imagePullPolicy: IfNotPresent

    command:
    - /bin/sh
    - -ec

    args:
    - |
      echo "======================================"
      echo "Department Peer DB Repair"
      echo "======================================"

      echo
      echo "Checking peer storage..."
      ls -la /var/hyperledger/production

      echo
      echo "Checking MSP..."
      ls -la /var/hyperledger/msp
      ls -la /var/hyperledger/msp/signcerts
      ls -la /var/hyperledger/msp/keystore
      ls -la /var/hyperledger/msp/cacerts

      echo
      echo "Checking TLS..."
      ls -la /var/hyperledger/tls

      echo
      echo "Running:"
      echo "peer node rebuild-dbs"
      echo

      peer node rebuild-dbs

      echo
      echo "======================================"
      echo "REBUILD-DBS COMPLETED SUCCESSFULLY"
      echo "======================================"

    env:
    - name: FABRIC_CFG_PATH
      value: /etc/hyperledger/fabric

    - name: CORE_PEER_ID
      value: peer0.department.capstone.com

    - name: CORE_PEER_LOCALMSPID
      value: DepartmentMSP

    - name: CORE_PEER_MSPCONFIGPATH
      value: /var/hyperledger/msp

    - name: CORE_PEER_FILESYSTEMPATH
      value: /var/hyperledger/production

    - name: CORE_PEER_TLS_ENABLED
      value: "true"

    - name: CORE_PEER_TLS_CERT_FILE
      value: /var/hyperledger/tls/server.crt

    - name: CORE_PEER_TLS_KEY_FILE
      value: /var/hyperledger/tls/server.key

    - name: CORE_PEER_TLS_ROOTCERT_FILE
      value: /var/hyperledger/tls/ca.crt

    - name: CORE_LEDGER_STATE_STATEDATABASE
      value: CouchDB

    - name: CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS
      value: couchdb-department:5984

    - name: CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME
      valueFrom:
        secretKeyRef:
          name: blockgo-secrets
          key: COUCHDB_USER

    - name: CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD
      valueFrom:
        secretKeyRef:
          name: blockgo-secrets
          key: COUCHDB_PASS

    volumeMounts:

    # Peer ledger
    - name: peer-storage
      mountPath: /var/hyperledger/production

    # Fabric core.yaml
    - name: config
      mountPath: /etc/hyperledger/fabric/core.yaml
      subPath: core.yaml

    # MSP
    - name: crypto
      mountPath: /var/hyperledger/msp/signcerts/cert.pem
      subPath: msp-cert.pem

    - name: crypto
      mountPath: /var/hyperledger/msp/keystore/priv_sk
      subPath: msp-key.pem

    - name: crypto
      mountPath: /var/hyperledger/msp/cacerts/ca.pem
      subPath: msp-ca.pem

    - name: crypto
      mountPath: /var/hyperledger/msp/admincerts/admin-cert.pem
      subPath: admin-cert.pem

    # TLS
    - name: crypto
      mountPath: /var/hyperledger/tls/server.crt
      subPath: server.crt

    - name: crypto
      mountPath: /var/hyperledger/tls/server.key
      subPath: server.key

    - name: crypto
      mountPath: /var/hyperledger/tls/ca.crt
      subPath: ca.crt

  volumes:

  - name: peer-storage
    persistentVolumeClaim:
      claimName: ${PVC}

  - name: config
    configMap:
      name: fabric-common-config

  - name: crypto
    secret:
      secretName: ${CRYPTO_SECRET}
YAML


echo
echo "===== WAITING FOR REPAIR ====="

for i in $(seq 1 60); do

    STATUS="$(
      kubectl get pod "$REPAIR_POD" \
        -n "$NS" \
        -o jsonpath='{.status.phase}' \
        2>/dev/null || true
    )"

    echo "Status: ${STATUS:-Pending}"

    if [[ "$STATUS" == "Succeeded" ]]; then
        break
    fi

    if [[ "$STATUS" == "Failed" ]]; then
        echo
        echo "Repair failed."

        echo
        echo "===== REPAIR LOGS ====="

        kubectl logs "$REPAIR_POD" \
          -n "$NS" || true

        echo
        echo "Department peer will remain stopped."
        echo "DO NOT DELETE THE PVC."

        exit 1
    fi

    sleep 5
done


STATUS="$(
  kubectl get pod "$REPAIR_POD" \
    -n "$NS" \
    -o jsonpath='{.status.phase}' \
    2>/dev/null || true
)"


echo
echo "===== REPAIR LOGS ====="

kubectl logs "$REPAIR_POD" \
  -n "$NS" || true


if [[ "$STATUS" != "Succeeded" ]]; then

    echo
    echo "ERROR: Repair did not complete successfully."
    echo "Final status: $STATUS"
    echo
    echo "Department peer remains stopped."
    echo "DO NOT DELETE peer-department-pvc."

    exit 1
fi


echo
echo "===== DELETE REPAIR POD ====="

kubectl delete pod "$REPAIR_POD" \
  -n "$NS" \
  --ignore-not-found \
  --wait=true


echo
echo "===== START DEPARTMENT PEER ====="

kubectl scale deployment/"$PEER" \
  -n "$NS" \
  --replicas=1


echo
echo "===== WAIT FOR PEER ====="

if ! kubectl rollout status deployment/"$PEER" \
  -n "$NS" \
  --timeout=10m
then

    echo
    echo "ERROR: Department peer failed to become ready."

    POD="$(
      kubectl get pods \
        -n "$NS" \
        -l app="$PEER" \
        -o jsonpath='{.items[0].metadata.name}' \
        2>/dev/null || true
    )"

    if [[ -n "$POD" ]]; then

        echo
        echo "===== DEPARTMENT PEER LOGS ====="

        kubectl logs "$POD" \
          -n "$NS" \
          --tail=200 || true
    fi

    exit 1
fi


echo
echo "======================================"
echo "DEPARTMENT PEER RECOVERED"
echo "======================================"

kubectl get pods \
  -n "$NS" \
  -l app="$PEER" \
  -o wide