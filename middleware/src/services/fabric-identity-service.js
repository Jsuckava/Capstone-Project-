const crypto = require('crypto');
const { authenticateJWT, requireInternalKey, requireRegistrarOrInternal } = require('../shared/auth');
const { required, serviceUrl } = require('../shared/config');
const { requestJson } = require('../shared/internal-http');
const createLogger = require('../shared/logger');
const { normalizeAuthRole } = require('../shared/roles');
const { createServiceApp, installErrorHandler, listen } = require('../shared/service-app');
const { adminUser, cacheStats, enrollIdentity, ensureAdminEnrolled, registerIdentity, registrationPayload } = require('../fabric/ca-manager');
const { checkWallets, getWallet } = require('../fabric/wallet-manager');

const serviceName = 'fabric-identity-service';
const logger = createLogger(serviceName);
const { app, metrics } = createServiceApp(serviceName, logger);
const authenticate = authenticateJWT();

async function invalidateLedgerIdentity(username) {
    try {
        await requestJson(`${serviceUrl('LEDGER_SERVICE_URL', 'ledger-service', 4003)}/internal/gateways/${encodeURIComponent(username)}`, {
            method: 'DELETE', headers: { 'x-api-key': required('INTERNAL_API_KEY') }, timeoutMs: 5000
        });
    } catch (error) {
        logger.warn({ err: error, username }, 'Ledger cache invalidation was deferred; ledger verifies shared wallet existence before cache reuse');
    }
}

async function forceUpdateAndEnroll(username, password, role) {
    const config = await ensureAdminEnrolled(role);
    const wallet = await getWallet(config.role);
    const user = await adminUser(config, wallet);
    await config.client.newIdentityService().update(username, {
        type: registrationPayload(username, password, role).role,
        secret: password,
        max_enrollments: -1,
        attrs: registrationPayload(username, password, role).attrs
    }, user);
    return enrollIdentity(username, password, role);
}

async function ensureIdentity(username, password, role) {
    const normalized = normalizeAuthRole(role);
    const wallet = await getWallet(normalized);
    const existing = await wallet.get(username);
    if (existing) return { created: false, mspId: existing.mspId };
    try {
        const enrolled = await enrollIdentity(username, password, normalized);
        return { created: true, mspId: enrolled.identity.mspId };
    } catch (firstError) {
        await registerIdentity(username, password, normalized);
        try {
            const enrolled = await enrollIdentity(username, password, normalized);
            return { created: true, mspId: enrolled.identity.mspId };
        } catch (enrollmentError) {
            logger.warn({ username, role: normalized, err: enrollmentError }, 'Existing CA identity secret is stale; updating it for wallet recovery');
            const enrolled = await forceUpdateAndEnroll(username, password, normalized);
            return { created: true, mspId: enrolled.identity.mspId };
        }
    }
}

app.post('/internal/identities/ensure', requireInternalKey, async (req, res) => {
    const { username, password, role } = req.body || {};
    if (!username || !password || !role) return res.status(400).json({ error: 'username, password, and role are required.' });
    const result = await ensureIdentity(username, password, role);
    res.json({ status: 'success', ...result });
});

app.post('/internal/identities/bootstrap-registrar', requireInternalKey, async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password are required.' });
    const result = await ensureIdentity(username, password, 'registrar');
    res.json({ status: 'success', ...result });
});

app.post('/api/fabric/register-user', authenticate, requireRegistrarOrInternal, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const role = normalizeAuthRole(req.body?.role);
    if (!email || !role) return res.status(400).json({ error: 'email and role are required.' });
    const secret = req.body.password || crypto.randomBytes(12).toString('hex');
    const result = await ensureIdentity(email, secret, role);
    res.json({
        status: 'Success',
        message: result.created ? 'Blockchain wallet created successfully!' : 'Blockchain wallet already exists.',
        ...result
    });
});

app.post('/api/enroll', authenticate, requireRegistrarOrInternal, async (req, res) => {
    const { username, password } = req.body || {};
    const role = normalizeAuthRole(req.body?.role);
    if (!username || !password || !role) return res.status(400).json({ error: 'username, password, and role are required.' });
    const wallet = await getWallet(role);
    if (await wallet.get(username)) return res.json({ status: 'success', message: 'User is already enrolled in the wallet.' });
    await enrollIdentity(username, password, role);
    res.json({ status: 'success', message: `Wallet created for ${username}` });
});

app.post('/api/register', authenticate, requireRegistrarOrInternal, async (req, res) => {
    const { username, password } = req.body || {};
    const role = normalizeAuthRole(req.body?.role);
    if (!username || !password || !role) return res.status(400).json({ error: 'username, password, and role are required.' });
    const secret = await registerIdentity(username, password, role);
    res.status(201).json({ status: 'success', secret });
});

app.post('/api/revoke', authenticate, requireRegistrarOrInternal, async (req, res) => {
    const username = String(req.body?.username || '').trim();
    const role = normalizeAuthRole(req.body?.role);
    if (!username || !role) return res.status(400).json({ error: 'username and role are required.' });
    const config = await ensureAdminEnrolled(role);
    const wallet = await getWallet(role);
    await config.client.revoke({ enrollmentID: username, reason: 'Revoked by admin' }, await adminUser(config, wallet));
    await wallet.remove(username);
    await invalidateLedgerIdentity(username);
    res.json({ status: 'success', message: `Revoked ${username}` });
});

app.delete('/api/wallet/:username', authenticate, requireRegistrarOrInternal, async (req, res) => {
    let deleted = false;
    for (const role of ['registrar', 'faculty', 'department_admin']) {
        const wallet = await getWallet(role);
        if (await wallet.get(req.params.username)) { await wallet.remove(req.params.username); deleted = true; }
    }
    if (!deleted) return res.status(404).json({ status: 'error', message: 'Identity not found in wallet.' });
    await invalidateLedgerIdentity(req.params.username);
    res.json({ status: 'success', message: 'Wallet identity deleted.' });
});

app.get('/api/ready', async (req, res) => {
    try {
        const wallets = await checkWallets();
        metrics.setGauge('blockgo_ca_config_cache_entries', cacheStats().entries, 'Fabric CA configuration cache entries.');
        res.json({ status: 'ready', wallets });
    } catch (error) {
        res.status(503).json({ status: 'not_ready', error: error.message });
    }
});

installErrorHandler(app, logger);
listen(app, serviceName, 4002, logger);
