const { authenticateJWT, authorizeRole, requireInternalKey, requireRegistrarOrInternal } = require('../shared/auth');
const { required, serviceUrl } = require('../shared/config');
const { requestJson } = require('../shared/internal-http');
const createLogger = require('../shared/logger');
const { normalizeAuthRole } = require('../shared/roles');
const { createServiceApp, installErrorHandler, listen } = require('../shared/service-app');
const { cacheStats, checkFabricEndpoints, closeGateways, contractForUser, disconnect } = require('../fabric/gateway-manager');
const { checkWallets } = require('../fabric/wallet-manager');

const serviceName = 'ledger-service';
const logger = createLogger(serviceName);
const { app, metrics } = createServiceApp(serviceName, logger, { jsonLimit: '10mb' });
const authenticate = authenticateJWT();

async function lookupActiveUser(username) {
    return (await requestJson(`${serviceUrl('AUTH_SERVICE_URL', 'auth-service', 4001)}/internal/auth/identity`, {
        method: 'POST', headers: { 'x-api-key': required('INTERNAL_API_KEY') }, body: { username }
    })).user;
}

async function actorForRequest(req) {
    if (req.user) return req.user;
    if (!req.isInternal) throw Object.assign(new Error('Unauthorized caller identity access attempt.'), { status: 401 });
    const username = req.headers['x-user-identity'] || req.query.invokerId || req.body?.facultyId || req.body?.FacultyId || req.body?.ApprovedBy || req.body?.approvedBy;
    if (!username) throw Object.assign(new Error('The internal caller must provide x-user-identity.'), { status: 400 });
    return lookupActiveUser(username);
}

function shouldReconnect(error) {
    const message = String(error?.message || '').toLowerCase();
    return ['creator is malformed', 'access denied', 'unavailable', 'unknown', 'ssl', 'tls', 'certificate', 'handshake', 'failed to connect']
        .some((value) => message.includes(value));
}

function onLedgerError(username, error) {
    if (username && shouldReconnect(error)) disconnect(username, 'ledger-error');
}

async function contractWithReadFallback(actor) {
    try {
        return await contractForUser(actor.username, actor.dbRole);
    } catch (error) {
        if (actor.dbRole === 'student') throw error;
        logger.warn({ username: actor.username, err: error }, 'Using registrar read identity fallback');
        return contractForUser('system-admin-registrar', 'registrar');
    }
}

function decodeFacultyIdentity(grades) {
    if (!Array.isArray(grades)) return;
    for (const grade of grades) {
        const facultyId = grade.faculty_id || grade.facultyId || grade.FacultyId;
        if (!facultyId || facultyId.length <= 40 || facultyId.includes('@')) continue;
        try {
            const match = Buffer.from(facultyId, 'base64').toString('utf8').match(/CN=([^,]+)/);
            if (!match?.[1]) continue;
            if (grade.faculty_id) grade.faculty_id = match[1];
            if (grade.facultyId) grade.facultyId = match[1];
            if (grade.FacultyId) grade.FacultyId = match[1];
        } catch { /* keep the original identity */ }
    }
}

app.get('/api/all-grades', authenticate, async (req, res) => {
    let actor;
    try {
        actor = await actorForRequest(req);
        let contract = await contractWithReadFallback(actor);
        let result;
        try { result = await contract.evaluateTransaction('GetAllGrades'); }
        catch (error) {
            if (!shouldReconnect(error) || actor.dbRole === 'student') throw error;
            disconnect(actor.username, 'read-fallback');
            contract = await contractForUser('system-admin-registrar', 'registrar');
            result = await contract.evaluateTransaction('GetAllGrades');
        }
        let grades;
        try { grades = JSON.parse(result.toString()); }
        catch { return res.json({ status: 'success', data: result.toString() }); }
        // Go marshals a nil grade slice as JSON null when the ledger has no records.
        // Normalize only that valid empty-ledger result; malformed non-array payloads
        // must still surface as errors instead of being reported as "no records".
        if (grades === null) grades = [];
        if (!Array.isArray(grades)) throw new Error('The grade ledger returned an invalid response.');
        decodeFacultyIdentity(grades);
        const role = normalizeAuthRole(actor.dbRole);
        if (role === 'student') {
            const base = actor.username.split('@')[0].toLowerCase();
            grades = grades.filter((grade) => [grade.student_hash, grade.studentId, grade.student_id]
                .filter(Boolean).some((value) => [actor.username.toLowerCase(), base].includes(String(value).toLowerCase())));
        } else if (role === 'faculty') {
            grades = grades.filter((grade) => String(grade.faculty_id || grade.facultyId || '').toLowerCase() === actor.username.toLowerCase());
        } else if (role === 'department_admin') {
            const allowed = [actor.scope?.department, actor.scope?.programCode, actor.scope?.programName]
                .filter(Boolean).map((value) => String(value).toUpperCase());
            grades = grades.filter((grade) => {
                const program = String(grade.program || grade.course || '').toUpperCase();
                const subject = String(grade.subject_code || '').toUpperCase();
                return allowed.some((value) => program.includes(value) || subject.includes(value) || (value.startsWith('BS') && program.includes(value.slice(2))));
            });
        }
        res.json({ status: 'success', data: grades });
    } catch (error) {
        onLedgerError(actor?.username, error);
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.get('/api/student-transactions', authenticate, async (req, res) => {
    let actor;
    try {
        actor = await actorForRequest(req);
        if (normalizeAuthRole(actor.dbRole) !== 'student') return res.status(403).json({ error: 'Student transaction history is available only to the authenticated student.' });
        const result = await (await contractForUser(actor.username, 'student')).evaluateTransaction('GetStudentTransactions');
        res.json({ status: 'success', data: JSON.parse(result.toString()) });
    } catch (error) {
        onLedgerError(actor?.username, error);
        logger.error({ err: error, username: actor?.username }, 'Student transaction history query failed');
        res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Unable to retrieve transaction history' : error.message });
    }
});

app.get('/api/grade-history/:id', authenticate, async (req, res) => {
    let actor;
    try {
        actor = await actorForRequest(req);
        const role = normalizeAuthRole(actor.dbRole);
        if (!['faculty', 'department_admin', 'registrar'].includes(role)) return res.status(403).json({ error: 'Grade audit history is restricted to authorized academic staff.' });
        const contract = await contractForUser(actor.username, role);
        const current = JSON.parse((await contract.evaluateTransaction('ReadGrade', req.params.id)).toString());
        if (role === 'faculty' && String(current.faculty_id || '').toLowerCase() !== actor.username.toLowerCase()) {
            return res.status(403).json({ error: 'Faculty may view history only for grades they submitted.' });
        }
        if (role === 'department_admin') {
            const recordProgram = String(current.program || current.course || '').toLowerCase();
            const allowed = [actor.scope?.department, actor.scope?.programCode, actor.scope?.programName].filter(Boolean).map((value) => String(value).toLowerCase());
            if (!allowed.includes(recordProgram)) return res.status(403).json({ error: 'Chairpersons may view history only for their assigned academic program.' });
        }
        const history = await contract.evaluateTransaction('GetGradeHistory', req.params.id);
        res.json({ status: 'success', data: JSON.parse(history.toString()) });
    } catch (error) {
        onLedgerError(actor?.username, error);
        res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Unable to retrieve grade history' : error.message });
    }
});

app.post('/api/fabric/audit-event', authenticate, requireRegistrarOrInternal, async (req, res) => {
    let actor;
    try {
        actor = await actorForRequest(req);
        if (normalizeAuthRole(actor.dbRole) !== 'registrar') return res.status(403).json({ error: 'A registered Registrar ledger identity is required.' });
        const result = await (await contractForUser(actor.username, 'registrar')).submitTransaction('CreateAuditEvent', JSON.stringify(req.body));
        res.status(201).json({ status: 'success', data: JSON.parse(result.toString()) });
    } catch (error) {
        onLedgerError(actor?.username, error);
        res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Unable to record audit event' : error.message });
    }
});

app.post('/api/issue-grade', authenticate, authorizeRole(['faculty', 'department_admin']), async (req, res) => {
    const actor = await actorForRequest(req);
    try {
        const result = await (await contractForUser(actor.username, actor.dbRole)).submitTransaction('IssueGrade', JSON.stringify(req.body));
        res.status(201).json({ status: 'success', message: 'Grade recorded', details: result.toString() });
    } catch (error) { onLedgerError(actor.username, error); throw error; }
});

app.get('/api/get-grade/:id', authenticate, async (req, res) => {
    const actor = await actorForRequest(req);
    try {
        const contract = await contractWithReadFallback(actor);
        const record = JSON.parse((await contract.evaluateTransaction('ReadGrade', req.params.id)).toString());
        if (actor.dbRole === 'student') {
            const identifiers = [record.student_hash, record.student_id, record.studentId].filter(Boolean).map((value) => String(value).toLowerCase());
            if (!identifiers.includes(actor.username.toLowerCase()) && !identifiers.includes(actor.username.split('@')[0].toLowerCase())) {
                return res.status(403).json({ error: 'Students may retrieve only their own grade records.' });
            }
        }
        res.json(record);
    } catch (error) { onLedgerError(actor.username, error); res.status(404).json({ error: process.env.NODE_ENV === 'production' ? 'Record not found' : error.message }); }
});

function submitRoute(path, roles, transaction, message, status = 200, withBody = false) {
    app.post(path, authenticate, authorizeRole(roles), async (req, res) => {
        const actor = await actorForRequest(req);
        try {
            const args = withBody ? [JSON.stringify(req.body)] : [req.params.id];
            if (transaction === 'ReturnGrade') args.push(req.body?.note || 'Returned for revision');
            const result = await (await contractForUser(actor.username, actor.dbRole)).submitTransaction(transaction, ...args);
            res.status(status).json({ status: 'success', message, ...(result?.length ? { details: result.toString() } : {}) });
        } catch (error) { onLedgerError(actor.username, error); throw error; }
    });
}

submitRoute('/api/update-grade', ['faculty', 'department_admin', 'registrar'], 'UpdateGrade', 'Grade updated', 200, true);
submitRoute('/api/approve-grade/:id', ['department_admin', 'registrar'], 'ApproveGrade', 'Grade approved');
submitRoute('/api/finalize-grade/:id', ['registrar'], 'FinalizeRecord', 'Record finalized');
submitRoute('/api/return-grade/:id', ['department_admin', 'registrar'], 'ReturnGrade', 'Record returned for revision');

app.post('/api/batch-issue-grade', authenticate, async (req, res) => {
    const actor = await actorForRequest(req);
    const role = normalizeAuthRole(actor.dbRole);
    if (!['faculty', 'department_admin'].includes(role)) return res.status(403).json({ error: 'The authenticated account is not permitted to issue grades.' });
    try {
        const result = await (await contractForUser(actor.username, role)).submitTransaction('IssueBatchGrades', JSON.stringify(req.body));
        res.status(201).json({ status: 'success', message: 'Batch grades recorded', facultyId: actor.username, details: result.toString() });
    } catch (error) { onLedgerError(actor.username, error); throw error; }
});

app.delete('/internal/gateways/:username', requireInternalKey, (req, res) => {
    res.json({ status: 'success', disconnected: disconnect(req.params.username, 'identity-change') });
});

app.get('/api/ready', async (req, res) => {
    try {
        const wallets = await checkWallets();
        const fabric = await checkFabricEndpoints();
        const stats = cacheStats();
        metrics.setGauge('blockgo_gateway_cache_entries', stats.entries, 'Fabric Gateway cache entries.');
        metrics.setGauge('blockgo_gateway_cache_max_entries', stats.maxEntries, 'Fabric Gateway cache capacity.');
        res.json({ status: 'ready', gatewayCache: stats, wallets, fabric });
    } catch (error) { res.status(503).json({ status: 'not_ready', error: error.message }); }
});

installErrorHandler(app, logger);
listen(app, serviceName, 4003, logger, closeGateways);
