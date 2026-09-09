const http = require('http');
const express = require('express');
const { corsOrigins } = require('../shared/config');
const createLogger = require('../shared/logger');
const { createMetrics } = require('../shared/metrics');
const { requestJson } = require('../shared/internal-http');
const { resolveRoute, serviceTargets } = require('../shared/route-map');
const { listen } = require('../shared/service-app');

const serviceName = 'middleware-api';
const logger = createLogger(serviceName);
const metrics = createMetrics(serviceName);
const app = express();
const allowedOrigins = corsOrigins();

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
app.use(metrics.middleware);
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && !allowedOrigins.includes(origin)) {
        if (req.method === 'OPTIONS') return res.status(403).json({ error: 'Origin is not allowed.' });
    } else if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-api-key, x-user-identity');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.get('/api/health', (req, res) => res.json({ status: 'operational', service: serviceName, architecture: 'microservices' }));
app.get('/api/ready', async (req, res) => {
    const checks = await Promise.all(Object.entries(serviceTargets()).map(async ([name, url]) => {
        try {
            const result = await requestJson(`${url}/api/ready`, { timeoutMs: 3000 });
            return [name, { ready: true, status: result.status }];
        } catch (error) {
            return [name, { ready: false, error: error.message }];
        }
    }));
    const services = Object.fromEntries(checks);
    const ready = Object.values(services).every((check) => check.ready);
    res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'not_ready', services });
});
app.get('/metrics', (req, res) => res.type('text/plain; version=0.0.4').send(metrics.render()));

app.use((req, res) => {
    const pathname = new URL(req.originalUrl, 'http://middleware.local').pathname;
    const service = resolveRoute(pathname);
    if (!service) return res.status(404).json({ error: 'Unknown middleware API route.' });
    const target = new URL(serviceTargets()[service]);
    const proxy = http.request({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port,
        method: req.method,
        path: req.originalUrl,
        headers: { ...req.headers, host: target.host, 'x-forwarded-host': req.headers.host || '' },
        timeout: Number(process.env.PROXY_TIMEOUT_MS || 180000)
    }, (upstream) => {
        res.statusCode = upstream.statusCode || 502;
        for (const [name, value] of Object.entries(upstream.headers)) {
            if (value !== undefined) res.setHeader(name, value);
        }
        upstream.pipe(res);
    });
    proxy.on('timeout', () => proxy.destroy(new Error('Upstream service timeout.')));
    proxy.on('error', (error) => {
        logger.error({ err: error, service, path: req.originalUrl }, 'Upstream request failed');
        if (!res.headersSent) res.status(503).json({ error: `${service} service is unavailable.` });
        else res.end();
    });
    req.pipe(proxy);
});

listen(app, serviceName, 4000, logger);
