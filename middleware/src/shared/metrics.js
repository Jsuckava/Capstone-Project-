const buckets = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

function escapeLabel(value) {
    return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function createMetrics(serviceName) {
    const startedAt = Date.now();
    const requests = new Map();
    const gauges = new Map();

    function observe(method, route, status, durationSeconds) {
        const key = JSON.stringify([method, route || 'unmatched', status]);
        const metric = requests.get(key) || { count: 0, sum: 0, buckets: buckets.map(() => 0) };
        metric.count += 1;
        metric.sum += durationSeconds;
        buckets.forEach((limit, index) => {
            if (durationSeconds <= limit) metric.buckets[index] += 1;
        });
        requests.set(key, metric);
    }

    function middleware(req, res, next) {
        if (req.path === '/metrics') return next();
        const started = process.hrtime.bigint();
        res.on('finish', () => observe(
            req.method,
            req.route?.path || req.path,
            res.statusCode,
            Number(process.hrtime.bigint() - started) / 1e9
        ));
        next();
    }

    function setGauge(name, value, help = name) {
        gauges.set(name, { value: Number(value) || 0, help });
    }

    function render() {
        const lines = [
            '# HELP blockgo_service_info Running BlockGo service.',
            '# TYPE blockgo_service_info gauge',
            `blockgo_service_info{service="${escapeLabel(serviceName)}"} 1`,
            '# HELP process_uptime_seconds Process uptime in seconds.',
            '# TYPE process_uptime_seconds gauge',
            `process_uptime_seconds ${((Date.now() - startedAt) / 1000).toFixed(3)}`,
            '# HELP http_requests_total Total HTTP requests.',
            '# TYPE http_requests_total counter',
            '# HELP http_request_duration_seconds HTTP request duration.',
            '# TYPE http_request_duration_seconds histogram'
        ];
        for (const [key, metric] of requests) {
            const [method, route, status] = JSON.parse(key);
            const labels = `service="${escapeLabel(serviceName)}",method="${escapeLabel(method)}",route="${escapeLabel(route)}",status="${status}"`;
            lines.push(`http_requests_total{${labels}} ${metric.count}`);
            metric.buckets.forEach((count, index) => lines.push(`http_request_duration_seconds_bucket{${labels},le="${buckets[index]}"} ${count}`));
            lines.push(`http_request_duration_seconds_bucket{${labels},le="+Inf"} ${metric.count}`);
            lines.push(`http_request_duration_seconds_sum{${labels}} ${metric.sum}`);
            lines.push(`http_request_duration_seconds_count{${labels}} ${metric.count}`);
        }
        for (const [name, gauge] of gauges) {
            lines.push(`# HELP ${name} ${gauge.help}`, `# TYPE ${name} gauge`, `${name} ${gauge.value}`);
        }
        return `${lines.join('\n')}\n`;
    }

    return { middleware, observe, render, setGauge };
}

module.exports = { createMetrics };
