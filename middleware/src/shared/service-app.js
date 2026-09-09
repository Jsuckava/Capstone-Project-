const express = require('express');
const { createMetrics } = require('./metrics');

function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
}

function createServiceApp(serviceName, logger, options = {}) {
    const app = express();
    const metrics = createMetrics(serviceName);
    app.disable('x-powered-by');
    app.set('trust proxy', 1);
    app.use(securityHeaders);
    app.use(metrics.middleware);
    if (options.json !== false) app.use(express.json({ limit: options.jsonLimit || '2mb' }));
    app.get('/metrics', (req, res) => res.type('text/plain; version=0.0.4').send(metrics.render()));
    app.get('/api/health', (req, res) => res.status(200).json({ status: 'operational', service: serviceName }));
    return { app, metrics };
}

function installErrorHandler(app, logger) {
    app.use((err, req, res, next) => {
        logger.error({ err, method: req.method, path: req.originalUrl }, 'Unhandled service error');
        if (res.headersSent) return next(err);
        res.status(err.status || 500).json({ error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message });
    });
}

function listen(app, serviceName, defaultPort, logger, shutdown) {
    const port = Number(process.env.PORT || defaultPort);
    const server = app.listen(port, '0.0.0.0', () => logger.info({ port }, `${serviceName} online`));
    const stop = (signal) => {
        logger.info({ signal }, 'Graceful shutdown started');
        server.close(async () => {
            try { if (shutdown) await shutdown(); } finally { process.exit(0); }
        });
        setTimeout(() => process.exit(1), Number(process.env.SHUTDOWN_GRACE_MS || 30000)).unref();
    };
    process.once('SIGINT', () => stop('SIGINT'));
    process.once('SIGTERM', () => stop('SIGTERM'));
    return server;
}

module.exports = { createServiceApp, installErrorHandler, listen };
