# Three-Host Kubernetes HA Deployment Prompt

Use this prompt when asking an engineer or AI assistant to design the production deployment for this project.

```text
You are a senior Kubernetes, Hyperledger Fabric, PostgreSQL, and multi-region HA architect.

Project context:
- Repo: BLOCKGO / Capstone project.
- Main Kubernetes manifests live only in network/k8s.
- Components: React frontend, Node middleware API, .NET client app, Hyperledger Fabric orderers/peers/CAs, Go chaincode as a service, PostgreSQL, CouchDB wallets, IPFS private network.
- Current namespaces model campuses:
  - plv-main-campus
  - plv-annex-campus
  - plv-pubad-campus
  - plv-fabric
- Goal: deploy to three separate web hosts or cloud providers, one host per campus, while exposing only one public domain, for high availability and no single point of failure.

Target topology:
- Host A: Main campus Kubernetes cluster.
- Host B: Annex campus Kubernetes cluster.
- Host C: PubAd campus Kubernetes cluster.
- Public domain: plv-blockgo.com
- The domain must route to all three clusters through a global load balancer or health-checked DNS, such as Cloudflare Load Balancer, AWS Route 53 failover/latency records, NS1, or equivalent.
- Each host must have its own ingress controller, TLS certificate for the same domain, container runtime, persistent storage class, monitoring, and backups.
- Clusters must communicate over a private encrypted network, such as WireGuard, Tailscale, Cilium ClusterMesh, or provider VPC peering.

Hard requirements:
1. One public domain only: plv-blockgo.com
2. All three sites must be active and able to serve frontend/API traffic.
3. Loss of any one host must not take the system offline.
4. Fabric orderer quorum must survive one host failure.
5. Each campus must keep local copies of ledger, IPFS data, wallet data, and application database state.
6. Data replication must be explicit, observable, encrypted in transit, backed up, and tested.
7. Writes must be idempotent. Every cross-site event must have a stable event ID to prevent duplicates.

Recommended architecture:
- Global entry:
  - Put Cloudflare/AWS Route 53/NS1 in front of the three ingress IPs.
  - Health check https://plv-blockgo.com/health or /api/health on each host.
  - Use low TTL, automatic failover, and session affinity only if the app requires it.
- Kubernetes:
  - Use one cluster per host.
  - Create Kustomize overlays or Helm values for main, annex, and pubad.
  - Keep shared manifests in network/k8s/base and host-specific patches in network/k8s/overlays/{main,annex,pubad}.
  - Use a shared image registry instead of building images independently on each host.
- Fabric:
  - Distribute orderers across the three hosts.
  - Prefer 3 or 5 voting orderers; with the current 6-orderer layout, place 2 orderers per host and confirm quorum behavior.
  - Expose orderer/peer endpoints through private inter-cluster DNS names or private load balancers.
  - Keep peer MSP/TLS secrets unique and synchronized through sealed-secrets, external-secrets, or a vault.
- Application:
  - Run frontend, middleware, and client-app on every host.
  - Configure every instance to reach local services first, then fail over to remote services.
  - Add /health and /ready endpoints that check database, Fabric gateway, IPFS, and dependent APIs.
- IPFS:
  - Run IPFS nodes on all three hosts using the same private swarm key.
  - Configure peering across hosts.
  - Pin critical content on all hosts and verify replication with scheduled checks.
- PostgreSQL:
  - Do not assume simple primary/replica YAML gives active-active writes.
  - Choose one of these models:
    A. Safer model: one global writer with async replicas and automatic failover using Patroni/repmgr plus HAProxy/pgBouncer.
    B. Active-active model: use PostgreSQL logical replication with conflict policy, BDR/Bucardo, or move to a PostgreSQL-compatible distributed database such as YugabyteDB/CockroachDB after app compatibility testing.
    C. Ledger-first model: treat Fabric as the source of truth and let each site rebuild local Postgres read models from Fabric events.
  - For simultaneous writes across campuses, require deterministic conflict handling: campus ownership, last-write-wins only for noncritical fields, version numbers, unique IDs, and idempotent outbox events.
- CouchDB wallets:
  - Prefer enrolling identities through Fabric CA and storing wallet material in a secure external secret store.
  - If CouchDB wallet replication is kept, configure filtered replication and backup/restore drills.
- Backups:
  - Nightly encrypted PostgreSQL backups from each host.
  - Fabric channel artifacts, MSP material, CA material, and private keys backed up to secure storage.
  - IPFS pin inventory exported and checked.

Deliverables to produce:
1. A concrete three-host architecture diagram in text.
2. DNS/load-balancer setup steps for one domain pointing to all three ingress endpoints.
3. Kubernetes overlay structure and exact files to create.
4. Per-host deployment commands.
5. Fabric orderer/peer endpoint plan across hosts.
6. Database replication design with chosen conflict rules.
7. IPFS private swarm setup across hosts.
8. Secret management plan.
9. Backup and disaster recovery plan.
10. Verification checklist proving one host can fail while the system continues serving traffic.

Deployment sequence:
1. Build and push images to a shared registry:
   - plv/frontend:<version>
   - plv/fabric-middleware:<version>
   - plv/client-app:<version>
   - plv/registrar-chaincode:<version>
2. Provision Host A, Host B, and Host C Kubernetes clusters.
3. Create private network connectivity between clusters.
4. Install ingress-nginx and cert-manager on each cluster.
5. Apply shared namespaces, secrets, configmaps, and storage classes.
6. Deploy Fabric CAs, orderers, peers, and chaincode endpoints.
7. Join orderers/peers into the Fabric channel and verify quorum.
8. Deploy PostgreSQL using the selected replication model.
9. Deploy IPFS nodes and verify cross-host peering and pin replication.
10. Deploy middleware, client app, frontend, and ingress on every host.
11. Configure global DNS/load balancer for blockgo.example.com.
12. Run failover tests:
    - Stop Host A and verify Host B/C serve traffic.
    - Stop Host B and verify Host A/C serve traffic.
    - Stop Host C and verify Host A/B serve traffic.
    - Verify no duplicate writes, lost events, or Fabric quorum loss.

Important warning:
If the application writes directly to local PostgreSQL on all three hosts without conflict-safe multi-master replication, the system can split-brain. For true active-active behavior, either make Fabric the write source of truth and replicate read models, or use a proven distributed database/replication layer with tested conflict rules.
```