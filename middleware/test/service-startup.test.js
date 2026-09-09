const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const services = [
    ['api-gateway.js', 14100, 'middleware-api'],
    ['auth-service.js', 14101, 'auth-service'],
    ['fabric-identity-service.js', 14102, 'fabric-identity-service'],
    ['ledger-service.js', 14103, 'ledger-service'],
    ['grade-upload-service.js', 14104, 'grade-upload-service'],
    ['settings-service.js', 14105, 'settings-service']
];

async function waitForHealth(port, child) {
    // Fabric SDK module loading is slow on Windows/virus-scanned workspaces.
    const startupTimeoutMs = Number(process.env.SERVICE_STARTUP_TIMEOUT_MS || 120000);
    const deadline = Date.now() + startupTimeoutMs;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`Service exited with code ${child.exitCode}.`);
        try {
            const response = await fetch(`http://127.0.0.1:${port}/api/health`);
            if (response.ok) return response.json();
        } catch { /* service is still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Service on port ${port} did not become healthy.`);
}

for (const [entrypoint, port, expectedName] of services) {
    test(`${expectedName} starts as an independent process`, async (context) => {
        const output = [];
        const child = spawn(process.execPath, [path.join('src', 'services', entrypoint)], {
            cwd: path.resolve(__dirname, '..'),
            env: {
                ...process.env,
                NODE_ENV: 'production',
                PORT: String(port),
                JWT_SECRET: process.env.JWT_SECRET || 'test-jwt-secret-not-for-production',
                INTERNAL_API_KEY: process.env.INTERNAL_API_KEY || 'test-internal-key-not-for-production'
            },
            stdio: ['ignore', 'pipe', 'pipe']
        });
        child.stdout.on('data', (data) => output.push(data.toString()));
        child.stderr.on('data', (data) => output.push(data.toString()));
        context.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
        try {
            const health = await waitForHealth(port, child);
            assert.equal(health.service, expectedName);
        } catch (error) {
            throw new Error(`${error.message}\n${output.join('')}`);
        }
    });
}
