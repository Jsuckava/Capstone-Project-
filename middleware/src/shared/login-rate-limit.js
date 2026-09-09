const { ipKeyGenerator, rateLimit } = require('express-rate-limit');

function normalizedLoginIdentity(req) {
    return String(req.body?.username || '').trim().toLowerCase() || '<missing-account>';
}

function loginAttemptKey(req) {
    const source = ipKeyGenerator(req.ip || req.socket?.remoteAddress || 'unknown');
    return `${source}\u001f${normalizedLoginIdentity(req)}`;
}

function createLoginLimiter({ recordSecurityEvent, max = 5, windowMs = 15 * 60 * 1000 }) {
    return rateLimit({
        windowMs,
        max,
        keyGenerator: loginAttemptKey,
        standardHeaders: true,
        legacyHeaders: false,
        // Authentication failures are client errors. Successful logins and
        // service-side failures must never consume an account's attempt budget.
        skipSuccessfulRequests: true,
        requestWasSuccessful: (_req, res) => res.statusCode < 400 || res.statusCode >= 500,
        handler: async (req, res) => {
            if (recordSecurityEvent) {
                await recordSecurityEvent(
                    req,
                    'LOGIN_RATE_LIMIT',
                    'HIGH',
                    normalizedLoginIdentity(req),
                    'More than five failed login attempts were made for this account from the same source within fifteen minutes.'
                );
            }
            res.status(429).json({
                error: 'Too many failed login attempts for this account from this source. Please try again after 15 minutes.'
            });
        }
    });
}

module.exports = { createLoginLimiter, loginAttemptKey, normalizedLoginIdentity };
