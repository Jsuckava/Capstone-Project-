const jwt = require('jsonwebtoken');
const { jwtKey, required, serviceUrl } = require('./config');
const { requestJson } = require('./internal-http');
const { normalizeAuthRole } = require('./roles');

function internalKeyMatches(req) {
    return Boolean(process.env.INTERNAL_API_KEY) && req.headers['x-api-key'] === process.env.INTERNAL_API_KEY;
}

async function introspectToken(token, req) {
    return requestJson(`${serviceUrl('AUTH_SERVICE_URL', 'auth-service', 4001)}/internal/auth/introspect`, {
        method: 'POST',
        headers: { 'x-api-key': required('INTERNAL_API_KEY') },
        body: {
            token,
            sourceIp: req?.ip || req?.socket?.remoteAddress || null,
            requestPath: req?.originalUrl || req?.path || null,
            requestMethod: req?.method || null
        }
    });
}

function authenticateJWT(options = {}) {
    return async (req, res, next) => {
        if (internalKeyMatches(req)) {
            req.isInternal = true;
            return next();
        }
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required. Please provide a valid JWT or Internal API Key.' });
        }
        try {
            let user;
            if (options.localIntrospection) {
                user = jwt.verify(authHeader.slice(7), jwtKey());
                user.dbRole = normalizeAuthRole(user.dbRole || user.role);
            } else {
                user = (await introspectToken(authHeader.slice(7), req)).user;
            }
            req.user = user;
            return next();
        } catch (error) {
            return res.status(error.status === 503 ? 503 : 403).json({ error: error.status === 503 ? 'Account validation is temporarily unavailable.' : 'Invalid, expired, or revoked token.' });
        }
    };
}

function authorizeRole(allowedRoles) {
    const normalizedAllowed = allowedRoles.map(normalizeAuthRole);
    return (req, res, next) => {
        if (req.isInternal) return next();
        const role = normalizeAuthRole(req.user?.dbRole || req.user?.role);
        if (!role || !normalizedAllowed.includes(role)) return res.status(403).json({ error: `Access denied: role '${role || 'unknown'}' is not authorized.` });
        next();
    };
}

function requireRegistrarOrInternal(req, res, next) {
    if (req.isInternal || internalKeyMatches(req)) return next();
    if (normalizeAuthRole(req.user?.dbRole || req.user?.role) === 'registrar') return next();
    return res.status(403).json({ error: 'Access denied. Cryptographic operations require Registrar privileges or a valid Internal API Key.' });
}

function requireInternalKey(req, res, next) {
    if (!internalKeyMatches(req)) return res.status(403).json({ error: 'Forbidden: a valid internal API key is required.' });
    req.isInternal = true;
    next();
}

module.exports = { authenticateJWT, authorizeRole, internalKeyMatches, requireInternalKey, requireRegistrarOrInternal };
