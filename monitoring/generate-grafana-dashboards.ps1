param(
    [string]$OutputDirectory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

function New-PrometheusTarget {
    param([string]$Expression, [string]$Legend, [string]$Reference)
    [ordered]@{ expr = $Expression; legendFormat = $Legend; refId = $Reference }
}

function New-LokiTarget {
    param([string]$Expression, [string]$Reference = 'A')
    [ordered]@{ expr = $Expression; queryType = 'range'; refId = $Reference }
}

function New-Panel {
    param(
        [int]$Id,
        [string]$Title,
        [string]$Type,
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height,
        [object[]]$Targets,
        [string]$Unit = 'short',
        [string]$DatasourceType = 'prometheus',
        [string]$DatasourceUid = 'prometheus'
    )

    $panel = [ordered]@{
        id = $Id
        title = $Title
        type = $Type
        datasource = [ordered]@{ type = $DatasourceType; uid = $DatasourceUid }
        gridPos = [ordered]@{ h = $Height; w = $Width; x = $X; y = $Y }
        fieldConfig = [ordered]@{
            defaults = [ordered]@{
                unit = $Unit
                color = [ordered]@{ mode = 'palette-classic' }
                custom = [ordered]@{ drawStyle = 'line'; lineInterpolation = 'linear'; lineWidth = 1; fillOpacity = 10; showPoints = 'never' }
            }
            overrides = @()
        }
        options = [ordered]@{
            legend = [ordered]@{ displayMode = 'table'; placement = 'bottom'; calcs = @('lastNotNull', 'max') }
            tooltip = [ordered]@{ mode = 'multi'; sort = 'desc' }
        }
        targets = $Targets
    }

    if ($Type -eq 'stat') {
        $panel.options = [ordered]@{
            colorMode = 'value'
            graphMode = 'area'
            justifyMode = 'auto'
            orientation = 'auto'
            reduceOptions = [ordered]@{ calcs = @('lastNotNull'); fields = ''; values = $false }
            textMode = 'auto'
        }
    }
    elseif ($Type -eq 'gauge') {
        $panel.options = [ordered]@{
            orientation = 'auto'
            reduceOptions = [ordered]@{ calcs = @('lastNotNull'); fields = ''; values = $false }
            showThresholdLabels = $false
            showThresholdMarkers = $true
        }
    }
    elseif ($Type -eq 'logs') {
        $panel.options = [ordered]@{
            dedupStrategy = 'none'
            enableLogDetails = $true
            prettifyLogMessage = $false
            showCommonLabels = $false
            showLabels = $false
            showTime = $true
            sortOrder = 'Descending'
            wrapLogMessage = $true
        }
    }
    elseif ($Type -eq 'table') {
        $panel.options = [ordered]@{ showHeader = $true; cellHeight = 'sm' }
    }

    $panel
}

function New-Dashboard {
    param([string]$Title, [string]$Uid, [string[]]$Tags, [object[]]$Panels)
    [ordered]@{
        annotations = [ordered]@{ list = @() }
        editable = $false
        fiscalYearStartMonth = 0
        graphTooltip = 1
        links = @()
        panels = $Panels
        refresh = '15s'
        schemaVersion = 41
        tags = $Tags
        templating = [ordered]@{ list = @() }
        time = [ordered]@{ from = 'now-6h'; to = 'now' }
        timezone = 'browser'
        title = $Title
        uid = $Uid
        version = 1
        weekStart = ''
    }
}

function Write-Dashboard {
    param([string]$FileName, [object]$Dashboard)
    $path = Join-Path $OutputDirectory $FileName
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, ($Dashboard | ConvertTo-Json -Depth 100), $utf8NoBom)
}

$kubernetesPanels = @(
    (New-Panel 1 'Cluster Memory Utilization' 'gauge' 0 0 6 7 @(
        (New-PrometheusTarget 'sum(container_memory_working_set_bytes{namespace!=""}) / scalar(max(machine_memory_bytes))' 'cluster' 'A')
    ) 'percentunit'),
    (New-Panel 2 'Node Memory Capacity' 'stat' 6 0 6 7 @(
        (New-PrometheusTarget 'max(machine_memory_bytes)' 'capacity' 'A')
    ) 'bytes'),
    (New-Panel 3 'Running Pods' 'stat' 12 0 6 7 @(
        (New-PrometheusTarget 'sum(kube_pod_status_phase{phase="Running"})' 'running' 'A')
    )),
    (New-Panel 4 'Container Restarts (1h)' 'stat' 18 0 6 7 @(
        (New-PrometheusTarget 'sum(increase(kube_pod_container_status_restarts_total[1h]))' 'restarts' 'A')
    )),
    (New-Panel 5 'Memory by Namespace' 'timeseries' 0 7 12 8 @(
        (New-PrometheusTarget 'sum by (namespace) (container_memory_working_set_bytes{namespace!=""})' '{{namespace}}' 'A')
    ) 'bytes'),
    (New-Panel 6 'Top Pods by Working Set' 'timeseries' 12 7 12 8 @(
        (New-PrometheusTarget 'topk(15, sum by (namespace, pod) (container_memory_working_set_bytes{namespace!=""}))' '{{namespace}} / {{pod}}' 'A')
    ) 'bytes'),
    (New-Panel 7 'Container Memory Limit Utilization' 'timeseries' 0 15 12 8 @(
        (New-PrometheusTarget 'topk(15, sum by (namespace, pod) (container_memory_working_set_bytes{namespace=~"plv-.*"}) / sum by (namespace, pod) (kube_pod_container_resource_limits{namespace=~"plv-.*",resource="memory",unit="byte"}))' '{{namespace}} / {{pod}}' 'A')
    ) 'percentunit'),
    (New-Panel 8 'Pod Availability' 'timeseries' 12 15 12 8 @(
        (New-PrometheusTarget 'kube_deployment_status_replicas_available{namespace=~"plv-.*"}' '{{namespace}} / {{deployment}} available' 'A'),
        (New-PrometheusTarget 'kube_deployment_spec_replicas{namespace=~"plv-.*"}' '{{namespace}} / {{deployment}} desired' 'B')
    ))
)
Write-Dashboard 'grafana-kubernetes-memory.json' (New-Dashboard 'BlockGO / Kubernetes & Node Memory' 'blockgo-kubernetes-memory' @('blockgo','kubernetes','memory','system-admin') $kubernetesPanels)

$apiPanels = @(
    (New-Panel 1 'Request Rate' 'timeseries' 0 0 8 8 @(
        (New-PrometheusTarget 'sum by (service) (rate(http_requests_total[5m]))' '{{service}}' 'A')
    ) 'reqps'),
    (New-Panel 2 '5xx Error Rate' 'timeseries' 8 0 8 8 @(
        (New-PrometheusTarget 'sum by (service) (rate(http_requests_total{status=~"5.."}[5m]))' '{{service}}' 'A')
    ) 'reqps'),
    (New-Panel 3 'Error Percentage' 'timeseries' 16 0 8 8 @(
        (New-PrometheusTarget 'sum by (service) (rate(http_requests_total{status=~"4..|5.."}[5m])) / clamp_min(sum by (service) (rate(http_requests_total[5m])), 0.000001)' '{{service}}' 'A')
    ) 'percentunit'),
    (New-Panel 4 'API Latency Percentiles' 'timeseries' 0 8 12 8 @(
        (New-PrometheusTarget 'histogram_quantile(0.50, sum by (le, service) (rate(http_request_duration_seconds_bucket[5m])))' '{{service}} p50' 'A'),
        (New-PrometheusTarget 'histogram_quantile(0.95, sum by (le, service) (rate(http_request_duration_seconds_bucket[5m])))' '{{service}} p95' 'B'),
        (New-PrometheusTarget 'histogram_quantile(0.99, sum by (le, service) (rate(http_request_duration_seconds_bucket[5m])))' '{{service}} p99' 'C')
    ) 's'),
    (New-Panel 5 'Slow Routes (p95)' 'timeseries' 12 8 12 8 @(
        (New-PrometheusTarget 'topk(15, histogram_quantile(0.95, sum by (le, service, route) (rate(http_request_duration_seconds_bucket[5m]))))' '{{service}} {{route}}' 'A')
    ) 's'),
    (New-Panel 6 'Errors by Route and Status (1h)' 'table' 0 16 24 9 @(
        (New-PrometheusTarget 'sort_desc(sum by (service, route, status) (increase(http_requests_total{status=~"4..|5.."}[1h])))' '{{service}} {{route}} {{status}}' 'A')
    ))
)
Write-Dashboard 'grafana-api-observability.json' (New-Dashboard 'BlockGO / API Errors & Latency' 'blockgo-api-observability' @('blockgo','api','errors','latency','system-admin') $apiPanels)

$fabricPanels = @(
    (New-Panel 1 'Fabric Targets Up' 'stat' 0 0 8 7 @(
        (New-PrometheusTarget 'sum(up{job=~"fabric-peer|fabric-orderer"})' 'up' 'A')
    )),
    (New-Panel 2 'Peer Blockchain Height' 'timeseries' 8 0 8 7 @(
        (New-PrometheusTarget 'ledger_blockchain_height' '{{namespace}} / {{pod}} / {{channel}}' 'A')
    )),
    (New-Panel 3 'Raft Leaders' 'stat' 16 0 8 7 @(
        (New-PrometheusTarget 'sum(consensus_etcdraft_is_leader)' 'leaders' 'A')
    )),
    (New-Panel 4 'Peer gRPC Requests' 'timeseries' 0 7 12 8 @(
        (New-PrometheusTarget 'sum by (namespace, pod, service, method, code) (rate(grpc_server_unary_requests_completed{job="fabric-peer"}[5m]))' '{{namespace}} / {{pod}} / {{service}} / {{method}} / {{code}}' 'A')
    ) 'ops'),
    (New-Panel 5 'Peer gRPC p95 Duration' 'timeseries' 12 7 12 8 @(
        (New-PrometheusTarget 'histogram_quantile(0.95, sum by (le, namespace, pod, service, method) (rate(grpc_server_unary_request_duration_bucket{job="fabric-peer"}[5m])))' '{{namespace}} / {{pod}} / {{service}} / {{method}}' 'A')
    ) 's'),
    (New-Panel 6 'Raft Committed Block Number' 'timeseries' 0 15 12 8 @(
        (New-PrometheusTarget 'consensus_etcdraft_committed_block_number' '{{namespace}} / {{pod}} / {{channel}}' 'A')
    )),
    (New-Panel 7 'Orderer Deliver Requests' 'timeseries' 12 15 12 8 @(
        (New-PrometheusTarget 'sum by (namespace, pod, channel) (rate(deliver_requests_received[5m]))' '{{namespace}} / {{pod}} / {{channel}}' 'A')
    ) 'ops')
)
Write-Dashboard 'grafana-fabric.json' (New-Dashboard 'BlockGO / Hyperledger Fabric Peers & Orderers' 'blockgo-fabric' @('blockgo','fabric','peer','orderer','system-admin') $fabricPanels)

$postgresPanels = @(
    (New-Panel 1 'PostgreSQL Up' 'stat' 0 0 6 7 @((New-PrometheusTarget 'pg_up' 'postgres' 'A'))),
    (New-Panel 2 'Database Size' 'stat' 6 0 6 7 @((New-PrometheusTarget 'pg_database_size_bytes{datname!~"template.*"}' '{{datname}}' 'A')) 'bytes'),
    (New-Panel 3 'Active Connections' 'stat' 12 0 6 7 @((New-PrometheusTarget 'sum(pg_stat_database_numbackends)' 'connections' 'A'))),
    (New-Panel 4 'Exporter Scrape Errors' 'stat' 18 0 6 7 @((New-PrometheusTarget 'pg_exporter_last_scrape_error' 'errors' 'A'))),
    (New-Panel 5 'Transactions' 'timeseries' 0 7 12 8 @(
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_xact_commit[5m]))' '{{datname}} commits' 'A'),
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_xact_rollback[5m]))' '{{datname}} rollbacks' 'B')
    ) 'ops'),
    (New-Panel 6 'Cache Hit Ratio' 'timeseries' 12 7 12 8 @(
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_blks_hit[5m])) / clamp_min(sum by (datname) (rate(pg_stat_database_blks_hit[5m]) + rate(pg_stat_database_blks_read[5m])), 0.000001)' '{{datname}}' 'A')
    ) 'percentunit'),
    (New-Panel 7 'Rows Changed' 'timeseries' 0 15 12 8 @(
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_tup_inserted[5m]))' '{{datname}} inserted' 'A'),
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_tup_updated[5m]))' '{{datname}} updated' 'B'),
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_tup_deleted[5m]))' '{{datname}} deleted' 'C')
    ) 'ops'),
    (New-Panel 8 'Deadlocks & Temporary Bytes' 'timeseries' 12 15 12 8 @(
        (New-PrometheusTarget 'sum by (datname) (increase(pg_stat_database_deadlocks[5m]))' '{{datname}} deadlocks' 'A'),
        (New-PrometheusTarget 'sum by (datname) (rate(pg_stat_database_temp_bytes[5m]))' '{{datname}} temp bytes/s' 'B')
    ))
)
Write-Dashboard 'grafana-postgresql.json' (New-Dashboard 'BlockGO / PostgreSQL' 'blockgo-postgresql' @('blockgo','postgresql','database','system-admin') $postgresPanels)

$workflowFilter = 'route=~".*(register|enroll|revoke|wallet|batch-upload|upload-grades|issue-grade|batch-issue-grade|audit-event|all-grades|student-transactions).*"'
$workflowPanels = @(
    (New-Panel 1 'Workflow Operations (1h)' 'stat' 0 0 8 7 @(
        (New-PrometheusTarget "sum(increase(http_requests_total{$workflowFilter}[1h]))" 'operations' 'A')
    )),
    (New-Panel 2 'Workflow Success Rate' 'gauge' 8 0 8 7 @(
        (New-PrometheusTarget ('sum(rate(http_requests_total{' + $workflowFilter + ',status=~"2..|3.."}[5m])) / clamp_min(sum(rate(http_requests_total{' + $workflowFilter + '}[5m])), 0.000001)') 'success' 'A')
    ) 'percentunit'),
    (New-Panel 3 'Workflow Failures (1h)' 'stat' 16 0 8 7 @(
        (New-PrometheusTarget ('sum(increase(http_requests_total{' + $workflowFilter + ',status=~"4..|5.."}[1h]))') 'failures' 'A')
    )),
    (New-Panel 4 'Identity Lifecycle Workflows' 'timeseries' 0 7 12 8 @(
        (New-PrometheusTarget 'sum by (route, status) (rate(http_requests_total{service="fabric-identity-service",route=~".*(register|enroll|revoke|wallet|identities).*"}[5m]))' '{{route}} / {{status}}' 'A')
    ) 'ops'),
    (New-Panel 5 'Grade & Ledger Workflows' 'timeseries' 12 7 12 8 @(
        (New-PrometheusTarget 'sum by (service, route, status) (rate(http_requests_total{route=~".*(batch-upload|upload-grades|issue-grade|batch-issue-grade|audit-event).*"}[5m]))' '{{service}} / {{route}} / {{status}}' 'A')
    ) 'ops'),
    (New-Panel 6 'Workflow p95 Latency' 'timeseries' 0 15 12 8 @(
        (New-PrometheusTarget "histogram_quantile(0.95, sum by (le, service, route) (rate(http_request_duration_seconds_bucket{$workflowFilter}[5m])))" '{{service}} / {{route}}' 'A')
    ) 's'),
    (New-Panel 7 'Fabric Client Caches' 'timeseries' 12 15 12 8 @(
        (New-PrometheusTarget 'blockgo_gateway_cache_entries' 'gateway entries' 'A'),
        (New-PrometheusTarget 'blockgo_gateway_cache_max_entries' 'gateway capacity' 'B'),
        (New-PrometheusTarget 'blockgo_ca_config_cache_entries' 'CA config entries' 'C')
    ))
)
Write-Dashboard 'grafana-workflows.json' (New-Dashboard 'BlockGO / Workflow Metrics' 'blockgo-workflows' @('blockgo','workflow','grades','identity','system-admin') $workflowPanels)

$logPanels = @(
    (New-Panel 1 'Log Lines by Namespace' 'timeseries' 0 0 12 8 @(
        (New-LokiTarget 'sum by (namespace) (count_over_time({cluster="blockgo"}[$__interval]))')
    ) 'short' 'loki' 'loki'),
    (New-Panel 2 'Errors and Exceptions' 'timeseries' 12 0 12 8 @(
        (New-LokiTarget 'sum by (namespace, app) (count_over_time({cluster="blockgo"} |~ "(?i)(error|exception|failed|42P08)" [$__interval]))')
    ) 'short' 'loki' 'loki'),
    (New-Panel 3 'BlockGO Application Logs' 'logs' 0 8 24 11 @(
        (New-LokiTarget '{cluster="blockgo",namespace=~"plv-.*"}')
    ) 'short' 'loki' 'loki'),
    (New-Panel 4 'Kubernetes Events' 'logs' 0 19 24 9 @(
        (New-LokiTarget '{cluster="blockgo",job="integrations/kubernetes/eventhandler"}')
    ) 'short' 'loki' 'loki')
)
Write-Dashboard 'grafana-logs.json' (New-Dashboard 'BlockGO / Kubernetes & Application Logs' 'blockgo-logs' @('blockgo','loki','logs','kubernetes','system-admin') $logPanels)

Write-Host "Generated six Grafana dashboards in $OutputDirectory"
