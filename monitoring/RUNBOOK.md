# BlockGO Middleware Microservices Operations Runbook

The stable `middleware-api` Deployment is the edge gateway. Route owners are
`auth-service`, `fabric-identity-service`, `ledger-service`,
`grade-upload-service`, and `settings-service`.

## System Admin Grafana

Grafana is provisioned with these System Admin dashboards:

- Kubernetes and node memory
- API errors and latency
- Hyperledger Fabric peers and orderers
- PostgreSQL
- BlockGO workflow metrics
- Kubernetes and application logs from Loki

Grafana has no public Ingress or NodePort. It is available only from the
**Grafana Observability** page in the System Admin portal. The backend issues a
short-lived HttpOnly session after verifying the `system_admin` role and then
proxies the embedded Grafana UI. Hiding the navigation item is not the security
boundary; the backend role check and private ClusterIP service are.

Check the observability workloads:

```bash
kubectl get pods -n plv-fabric -l tier=observability
kubectl get pod -n plv-main-campus -l app=postgres-exporter
kubectl logs -n plv-fabric deployment/prometheus --tail=100
kubectl logs -n plv-fabric deployment/loki --tail=100
kubectl logs -n plv-fabric deployment/alloy --tail=100
kubectl logs -n plv-fabric deployment/grafana --tail=100
```

Check Prometheus targets from inside the cluster:

```bash
kubectl run prometheus-check --rm -i --restart=Never -n plv-fabric --image=curlimages/curl -- \
  curl -fsS http://prometheus:9090/api/v1/targets
```

Check Loki ingestion:

```bash
kubectl run loki-check --rm -i --restart=Never -n plv-fabric --image=curlimages/curl -- \
  curl -fsS http://loki:3100/loki/api/v1/labels
```

## Memory Alerts

1. Check pod memory and restarts:

   ```bash
   kubectl top pods -n plv-fabric -l tier=application
   kubectl get pods -n plv-fabric -l tier=application -o wide
   kubectl describe pod -n plv-fabric -l tier=application
   ```

2. Check recent logs:

   ```bash
   kubectl logs -n plv-fabric deployment/middleware-api --tail=300
   kubectl logs -n plv-fabric deployment/auth-service --tail=300
   kubectl logs -n plv-fabric deployment/fabric-identity-service --tail=300
   kubectl logs -n plv-fabric deployment/ledger-service --tail=300
   kubectl logs -n plv-fabric deployment/grade-upload-service --tail=300
   kubectl logs -n plv-fabric deployment/settings-service --tail=300
   ```

3. Check OOM or eviction events:

   ```bash
   kubectl get events -n plv-fabric --sort-by=.lastTimestamp | grep -Ei "oom|evict|memory|middleware-api|auth-service|identity-service|ledger-service|upload-service|settings-service"
   ```

4. Inspect middleware metrics:

   ```bash
   kubectl port-forward -n plv-fabric svc/middleware-api 4000:4000
   curl http://127.0.0.1:4000/metrics
   ```

For a direct service readiness check, port-forward the owning Service and query
`/api/ready` on its declared port. Internal API routes still require the shared
internal key and should not be exposed through Ingress.

## Docker Checks

```bash
docker stats blockgo-api-gateway blockgo-auth-service blockgo-fabric-identity-service blockgo-ledger-service blockgo-grade-upload-service blockgo-settings-service --no-stream
docker top blockgo-ledger-service
docker exec blockgo-ledger-service node -e "console.log(process.memoryUsage())"
```

## Emergency Mitigation

1. Confirm whether memory is still rising after the gateway cache reaches steady state.
2. If the pod is close to OOM, temporarily raise the memory limit and roll the deployment.
3. If restarts continue, capture `--previous` logs and a heap snapshot before replacing pods.
4. Revert temporary limits after the leak source is fixed and a load test shows flat memory growth.
