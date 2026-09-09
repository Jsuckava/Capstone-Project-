const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const middlewareRoot = path.resolve(__dirname, '..', '..');
require('dotenv').config({ path: path.join(middlewareRoot, '.env') });
require('dotenv').config({ path: path.resolve(middlewareRoot, '..', 'network', '.env'), override: true });

function parsePositiveInt(value, fallback) {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function isContainerized() {
    return fs.existsSync('/.dockerenv') || fs.existsSync('/var/run/secrets/kubernetes.io');
}

function required(name) {
    const value = process.env[name];
    if (!value || !String(value).trim()) throw new Error(`${name} is required.`);
    return String(value).trim();
}

function jwtKey() {
    return crypto.createHash('sha256').update(required('JWT_SECRET')).digest();
}

function serviceUrl(environmentName, kubernetesName, localPort) {
    if (process.env[environmentName]) return process.env[environmentName].replace(/\/$/, '');
    return isContainerized()
        ? `http://${kubernetesName}.plv-fabric.svc.cluster.local:${localPort}`
        : `http://127.0.0.1:${localPort}`;
}

function corsOrigins() {
    return String(process.env.CORS_ORIGINS || process.env.FRONTEND_URL || 'http://localhost')
        .split(',').map((origin) => origin.trim()).filter(Boolean);
}

module.exports = { corsOrigins, isContainerized, jwtKey, middlewareRoot, parsePositiveInt, required, serviceUrl };
