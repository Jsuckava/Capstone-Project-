const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { closePools, getPools } = require('../shared/database');
const { jwtKey, required, serviceUrl, corsOrigins } = require('../shared/config');
const { requireInternalKey } = require('../shared/auth');
const { requestJson } = require('../shared/internal-http');
const createLogger = require('../shared/logger');
const { normalizeAuthRole } = require('../shared/roles');
const { createServiceApp, installErrorHandler, listen } = require('../shared/service-app');

const serviceName = 'auth-service';
const logger = createLogger(serviceName);
const { app } = createServiceApp(serviceName, logger);
const { read: dbRead, write: dbWrite } = getPools();

async function recordSecurityEvent(req, eventType, severity, attemptedIdentity, details) {
    try {
        await dbWrite.query(
            `INSERT INTO security_events
                (event_type, severity, attempted_identity, ip_address, request_path, request_method, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [eventType, severity, attemptedIdentity || null, req.ip || req.socket?.remoteAddress || null, req.originalUrl || req.path, req.method, details]
        );
    } catch (error) {
        logger.warn({ err: error, eventType }, 'Security event could not be persisted');
    }
}

async function activeUser(username) {
    if (!username) return null;
    const result = await dbRead.query(
        `SELECT u.id, u.email, u.role, u.status, u.is_active,
                ap.department, p.program_code, p.program_name
           FROM users u
           LEFT JOIN adminprofiles ap ON ap.user_id = u.id
           LEFT JOIN academic_programs p
             ON LOWER(p.program_name) = LOWER(ap.department)
             OR LOWER(p.program_code) = LOWER(ap.department)
          WHERE LOWER(u.email) = LOWER($1)
            AND LOWER(u.status) = 'approved'
            AND u.is_active = TRUE
          LIMIT 1`,
        [username]
    );
    if (!result.rows.length) return null;
    const user = result.rows[0];
    return {
        id: user.id,
        username: user.email,
        email: user.email,
        dbRole: normalizeAuthRole(user.role),
        scope: {
            department: user.department || null,
            programCode: user.program_code || null,
            programName: user.program_name || null
        }
    };
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    handler: async (req, res) => {
        await recordSecurityEvent(req, 'LOGIN_RATE_LIMIT', 'HIGH', req.body?.username, 'More than five login attempts were made within fifteen minutes.');
        res.status(429).json({ error: 'Too many login attempts from this IP, please try again after 15 minutes.' });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
        const normalizedUsername = String(username).trim().toLowerCase();
        const baseUsername = normalizedUsername.split('@')[0];
        const result = await dbRead.query(`
            SELECT u.*, sp.student_no
              FROM users u
              LEFT JOIN studentprofiles sp ON u.id = sp.user_id
             WHERE LOWER(u.email) = $1 OR LOWER(sp.student_no) = $1
                OR LOWER(u.email) = $2 OR LOWER(sp.student_no) = $2
             ORDER BY CASE
                WHEN LOWER(u.email) = $1 THEN 1 WHEN LOWER(sp.student_no) = $1 THEN 2
                WHEN LOWER(u.email) = $2 THEN 3 WHEN LOWER(sp.student_no) = $2 THEN 4 ELSE 5 END
             LIMIT 1`, [normalizedUsername, baseUsername]);
        if (!result.rows.length) {
            await recordSecurityEvent(req, 'FAILED_LOGIN', 'MEDIUM', normalizedUsername, 'Login failed for an unknown account identifier.');
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const account = result.rows[0];
        if (String(account.status).toLowerCase() !== 'approved' || account.is_active === false) {
            await recordSecurityEvent(req, 'INACTIVE_ACCOUNT_LOGIN', 'HIGH', account.email, 'A login was attempted for an inactive or unapproved account.');
            return res.status(403).json({ error: 'Account is not active or has not been approved.' });
        }
        if (!await bcrypt.compare(password, account.password_hash)) {
            await recordSecurityEvent(req, 'FAILED_LOGIN', 'MEDIUM', account.email, 'Login failed because the password did not match.');
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const role = normalizeAuthRole(account.role);
        if (role !== 'system_admin') {
            await requestJson(`${serviceUrl('IDENTITY_SERVICE_URL', 'fabric-identity-service', 4002)}/internal/identities/ensure`, {
                method: 'POST', timeoutMs: 45000,
                headers: { 'x-api-key': required('INTERNAL_API_KEY') },
                body: { username: account.email, password, role }
            });
        }
        const payload = { username: account.email, dbRole: role };
        const jwtOptions = { expiresIn: process.env.JWT_EXPIRES_IN || '12h' };
        if (process.env.JWT_ISSUER) jwtOptions.issuer = process.env.JWT_ISSUER;
        if (process.env.JWT_AUDIENCE) jwtOptions.audience = process.env.JWT_AUDIENCE;
        const token = jwt.sign(payload, jwtKey(), jwtOptions);
        res.status(200).json({ status: 'success', token, message: role === 'system_admin' ? 'System administrator logged in successfully.' : 'Use this token in the Authorization header: Bearer <token>' });
    } catch (error) {
        logger.error({ err: error }, 'Login failed');
        res.status(error.status && error.status < 500 ? error.status : 500).json({ error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message });
    }
});

app.post('/internal/auth/introspect', requireInternalKey, async (req, res) => {
    const originalRequest = {
        ip: req.body?.sourceIp,
        originalUrl: req.body?.requestPath,
        path: req.body?.requestPath,
        method: req.body?.requestMethod
    };
    let decoded;
    try {
        decoded = jwt.verify(req.body?.token, jwtKey());
    } catch (error) {
        const attempted = jwt.decode(req.body?.token || '')?.username || null;
        await recordSecurityEvent(originalRequest, 'INVALID_ACCESS_TOKEN', 'MEDIUM', attempted, 'An invalid or expired bearer token was rejected.');
        return res.status(403).json({ error: 'Invalid, expired, or revoked token.' });
    }
    try {
        const user = await activeUser(decoded.username || decoded.email);
        if (!user || user.dbRole !== normalizeAuthRole(decoded.dbRole || decoded.role)) {
            await recordSecurityEvent(originalRequest, 'REVOKED_ACCOUNT_TOKEN', 'HIGH', decoded.username || decoded.email, 'A token for an inactive, renamed, or role-changed account was rejected.');
            return res.status(403).json({ error: 'This account is inactive, changed, or no longer authorized.' });
        }
        return res.json({ active: true, user: { ...decoded, ...user } });
    } catch (error) {
        logger.error({ err: error }, 'Active-account introspection failed');
        return res.status(503).json({ error: 'Account validation is temporarily unavailable.' });
    }
});

app.post('/internal/auth/identity', requireInternalKey, async (req, res) => {
    const user = await activeUser(req.body?.username);
    if (!user) return res.status(404).json({ error: 'Active account not found.' });
    res.json({ user });
});

const passwordHashLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false
});
app.post('/api/crypto/hash-password', passwordHashLimiter, async (req, res) => {
    const password = req.body?.password;
    if (!password) return res.status(400).json({ error: 'Password is required.' });
    if (typeof password !== 'string' || password.length > 128) {
        return res.status(400).json({ error: 'Password must be a string of at most 128 characters.' });
    }
    res.json({ hash: await bcrypt.hash(password, 10) });
});

const passwordResetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false });
app.post('/api/forgot-password', passwordResetLimiter, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email is required.' });
    const result = await dbRead.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND is_active = TRUE AND LOWER(status) = \'approved\'', [email]);
    if (!result.rows.length) return res.json({ message: 'If that email exists, a password reset OTP has been sent.' });
    const otp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    await dbWrite.query('UPDATE password_reset_requests SET used_at = $1 WHERE LOWER(email) = LOWER($2) AND used_at IS NULL', [Date.now(), email]);
    await dbWrite.query('INSERT INTO password_reset_requests (user_id, email, otp_code, expires_at) VALUES ($1, $2, $3, $4)', [result.rows[0].id, email, otp, expiresAt]);
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: Number(process.env.SMTP_PORT || process.env.EMAIL_PORT || 587), secure: false,
        auth: { user: process.env.SMTP_USER || process.env.EMAIL_USER, pass: process.env.SMTP_PASS || process.env.EMAIL_PASS }
    });
    await transporter.sendMail({
        from: process.env.EMAIL_FROM || '"PLV Registrar BLOCKGO" <noreply@capstone.com>', to: email,
        subject: 'Password Reset Request',
        text: `Your PLV BlockGO password reset OTP is ${otp}. It expires in 10 minutes.`,
        html: `<p>Your PLV BlockGO password reset OTP is:</p><p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">${otp}</p><p>This code expires in 10 minutes.</p>`
    });
    res.json({ message: 'If that email exists, a password reset OTP has been sent.' });
});

app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail || !/^\d{6}$/.test(String(otp || '')) || typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
        return res.status(400).json({ error: 'Email, a valid six-digit OTP, and a password between 8 and 128 characters are required.' });
    }
    const result = await dbRead.query('SELECT request_id, user_id FROM password_reset_requests WHERE LOWER(email) = LOWER($1) AND otp_code = $2 AND expires_at > $3 AND used_at IS NULL ORDER BY created_at DESC LIMIT 1', [normalizedEmail, String(otp), Date.now()]);
    if (!result.rows.length) return res.status(400).json({ error: 'Invalid or expired OTP.' });
    await dbWrite.query('UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2', [await bcrypt.hash(newPassword, 10), result.rows[0].user_id]);
    await dbWrite.query('UPDATE password_reset_requests SET used_at = $1 WHERE request_id = $2', [Date.now(), result.rows[0].request_id]);
    res.json({ message: 'Password updated successfully. You can now log in.' });
});

app.get('/api/bootstrap', requireInternalKey, async (req, res) => {
    const systemEmail = process.env.BOOTSTRAP_SYSTEM_ADMIN_EMAIL || 'system-admin@plv.edu.ph';
    const systemPassword = process.env.BOOTSTRAP_SYSTEM_ADMIN_PASS || 'sysadmin123';
    const registrarEmail = process.env.BOOTSTRAP_REGISTRAR_EMAIL || 'registrar@plv.edu.ph';
    const registrarPassword = process.env.BOOTSTRAP_REGISTRAR_PASS || 'adminpw';
    const client = await dbWrite.connect();
    let committed = false;
    try {
        await client.query('BEGIN');
        let result = await client.query('SELECT id FROM users WHERE email = $1', [systemEmail]);
        if (!result.rows.length) {
            result = await client.query("INSERT INTO users (email, password_hash, role, status, is_active) VALUES ($1, $2, 'system_admin', 'APPROVED', TRUE) RETURNING id", [systemEmail, await bcrypt.hash(systemPassword, 10)]);
            await client.query("INSERT INTO adminprofiles (user_id, full_name, admin_level) VALUES ($1, 'System Administrator', 'system_admin')", [result.rows[0].id]);
        }
        result = await client.query('SELECT id, role, status, is_active FROM users WHERE email = $1', [registrarEmail]);
        if (!result.rows.length) {
            result = await client.query("INSERT INTO users (email, password_hash, role, status, is_active) VALUES ($1, $2, 'registrar', 'APPROVED', TRUE) RETURNING id, role, status, is_active", [registrarEmail, await bcrypt.hash(registrarPassword, 10)]);
            await client.query("INSERT INTO adminprofiles (user_id, full_name, admin_level, department) VALUES ($1, 'System Registrar', 'registrar', 'Registrar')", [result.rows[0].id]);
        }
        const bootstrapRegistrarIsActive = String(result.rows[0].role || '').toLowerCase() === 'registrar' &&
            String(result.rows[0].status || '').toLowerCase() === 'approved' && result.rows[0].is_active !== false;
        await client.query('COMMIT');
        committed = true;
        if (bootstrapRegistrarIsActive) {
            await requestJson(`${serviceUrl('IDENTITY_SERVICE_URL', 'fabric-identity-service', 4002)}/internal/identities/bootstrap-registrar`, {
                method: 'POST', timeoutMs: 45000,
                headers: { 'x-api-key': required('INTERNAL_API_KEY') },
                body: { username: registrarEmail, password: registrarPassword }
            });
        }
        res.json({ status: 'success', message: 'System administrator and registrar bootstrap is complete.' });
    } catch (error) {
        if (!committed) await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
});

app.get('/api/ready', async (req, res) => {
    try { await dbRead.query('SELECT 1'); res.json({ status: 'ready', database: 'connected' }); }
    catch { res.status(503).json({ status: 'not_ready', database: 'unavailable' }); }
});

installErrorHandler(app, logger);
listen(app, serviceName, 4001, logger, closePools);
