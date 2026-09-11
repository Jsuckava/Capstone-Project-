const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createLoginLimiter } = require('../src/shared/login-rate-limit');

async function withLoginServer(max, callback) {
    const app = express();
    const securityEvents = [];
    app.use(express.json());
    app.post('/api/login', createLoginLimiter({
        max,
        windowMs: 60_000,
        recordSecurityEvent: async (...args) => securityEvents.push(args)
    }), (req, res) => {
        if (req.body.password === 'correct') return res.json({ status: 'success' });
        if (req.body.password === 'server-error') return res.status(503).json({ error: 'unavailable' });
        return res.status(401).json({ error: 'invalid' });
    });
    const server = await new Promise((resolve) => {
        const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
    });
    try {
        const { port } = server.address();
        const login = (username, password) => fetch(`http://127.0.0.1:${port}/api/login`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        await callback({ login, securityEvents });
    } finally {
        await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
}

test('successful logins never consume the failed-attempt budget', async () => {
    await withLoginServer(2, async ({ login }) => {
        for (let attempt = 0; attempt < 6; attempt += 1) {
            assert.equal((await login('faculty@plv.edu.ph', 'correct')).status, 200);
        }
        assert.equal((await login('faculty@plv.edu.ph', 'wrong')).status, 401);
        assert.equal((await login('faculty@plv.edu.ph', 'wrong')).status, 401);
        assert.equal((await login('faculty@plv.edu.ph', 'correct')).status, 429);
    });
});

test('failed-attempt budgets are isolated by normalized account and source', async () => {
    await withLoginServer(2, async ({ login, securityEvents }) => {
        assert.equal((await login(' FACULTY@PLV.EDU.PH ', 'wrong')).status, 401);
        assert.equal((await login('faculty@plv.edu.ph', 'wrong')).status, 401);
        assert.equal((await login('faculty@plv.edu.ph', 'wrong')).status, 429);
        assert.equal((await login('student@plv.edu.ph', 'wrong')).status, 401);
        assert.equal(securityEvents.length, 1);
        assert.equal(securityEvents[0][3], 'faculty@plv.edu.ph');
    });
});

test('service failures do not consume the failed-attempt budget', async () => {
    await withLoginServer(1, async ({ login }) => {
        assert.equal((await login('faculty@plv.edu.ph', 'server-error')).status, 503);
        assert.equal((await login('faculty@plv.edu.ph', 'server-error')).status, 503);
        assert.equal((await login('faculty@plv.edu.ph', 'wrong')).status, 401);
        assert.equal((await login('faculty@plv.edu.ph', 'wrong')).status, 429);
    });
});
