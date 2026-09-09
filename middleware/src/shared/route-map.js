const { serviceUrl } = require('./config');

const routeDefinitions = [
    { service: 'auth', paths: [/^\/api\/login$/, /^\/api\/crypto\/hash-password$/, /^\/api\/forgot-password$/, /^\/api\/reset-password$/, /^\/api\/bootstrap$/] },
    { service: 'identity', paths: [/^\/api\/fabric\/register-user$/, /^\/api\/(enroll|register|revoke)$/, /^\/api\/wallet\/[^/]+$/] },
    { service: 'ledger', paths: [/^\/api\/all-grades$/, /^\/api\/student-transactions$/, /^\/api\/grade-history\/[^/]+$/, /^\/api\/fabric\/audit-event$/, /^\/api\/issue-grade$/, /^\/api\/get-grade\/[^/]+$/, /^\/api\/update-grade$/, /^\/api\/(approve-grade|finalize-grade|return-grade)\/[^/]+$/, /^\/api\/batch-issue-grade$/] },
    { service: 'upload', paths: [/^\/api\/(batch-upload|upload-grades)$/] },
    { service: 'settings', paths: [/^\/api\/SystemSettings(?:\/.*)?$/] }
];

function resolveRoute(pathname) {
    return routeDefinitions.find((definition) => definition.paths.some((pattern) => pattern.test(pathname)))?.service || null;
}

function serviceTargets() {
    return {
        auth: serviceUrl('AUTH_SERVICE_URL', 'auth-service', 4001),
        identity: serviceUrl('IDENTITY_SERVICE_URL', 'fabric-identity-service', 4002),
        ledger: serviceUrl('LEDGER_SERVICE_URL', 'ledger-service', 4003),
        upload: serviceUrl('UPLOAD_SERVICE_URL', 'grade-upload-service', 4004),
        settings: serviceUrl('SETTINGS_SERVICE_URL', 'settings-service', 4005)
    };
}

module.exports = { resolveRoute, routeDefinitions, serviceTargets };
