const { authenticateJWT, authorizeRole } = require('../shared/auth');
const { closePools, getPools } = require('../shared/database');
const createLogger = require('../shared/logger');
const { createServiceApp, installErrorHandler, listen } = require('../shared/service-app');

const serviceName = 'settings-service';
const logger = createLogger(serviceName);
const { app } = createServiceApp(serviceName, logger);
const { read: dbRead, write: dbWrite } = getPools();
const registrarOnly = [authenticateJWT(), authorizeRole(['registrar'])];

async function ensureSettingsTable() {
    await dbWrite.query('CREATE TABLE IF NOT EXISTS systemsettings (key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL)');
}

app.get('/api/SystemSettings/:key', async (req, res) => {
    await ensureSettingsTable();
    const result = await dbRead.query('SELECT value FROM systemsettings WHERE key = $1', [req.params.key]);
    res.json(result.rows.length
        ? { status: 'Success', value: result.rows[0].value }
        : { status: 'NotFound', value: null });
});

app.post('/api/SystemSettings', ...registrarOnly, async (req, res) => {
    const key = req.body?.key || req.body?.Key;
    const value = req.body?.value ?? req.body?.Value;
    if (!key) return res.status(400).json({ status: 'Error', message: 'Key is required' });
    await ensureSettingsTable();
    await dbWrite.query(
        'INSERT INTO systemsettings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
        [key, value]
    );
    res.json({ status: 'Success', message: 'Setting updated successfully' });
});

app.post('/api/SystemSettings/reset-season', ...registrarOnly, async (req, res) => {
    await dbWrite.query('TRUNCATE TABLE pending_grade_records');
    res.json({ status: 'Success', message: 'Encoding season reset. Staging area cleared.' });
});

app.get('/api/ready', async (req, res) => {
    try { await dbRead.query('SELECT 1'); res.json({ status: 'ready', database: 'connected' }); }
    catch { res.status(503).json({ status: 'not_ready', database: 'unavailable' }); }
});

installErrorHandler(app, logger);
listen(app, serviceName, 4005, logger, closePools);
