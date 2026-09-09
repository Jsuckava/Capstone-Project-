const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveRoute, routeDefinitions } = require('../src/shared/route-map');
const { normalizeAuthRole } = require('../src/shared/roles');
const { isRetryableCouchDbError } = require('../src/fabric/wallet-manager');

const expected = {
    '/api/login': 'auth', '/api/crypto/hash-password': 'auth', '/api/forgot-password': 'auth', '/api/reset-password': 'auth', '/api/bootstrap': 'auth',
    '/api/fabric/register-user': 'identity', '/api/enroll': 'identity', '/api/register': 'identity', '/api/revoke': 'identity', '/api/wallet/person@example.edu': 'identity',
    '/api/all-grades': 'ledger', '/api/student-transactions': 'ledger', '/api/grade-history/GRADE-1': 'ledger',
    '/api/fabric/audit-event': 'ledger', '/api/issue-grade': 'ledger', '/api/get-grade/GRADE-1': 'ledger',
    '/api/update-grade': 'ledger', '/api/approve-grade/GRADE-1': 'ledger', '/api/finalize-grade/GRADE-1': 'ledger',
    '/api/return-grade/GRADE-1': 'ledger', '/api/batch-issue-grade': 'ledger',
    '/api/batch-upload': 'upload', '/api/upload-grades': 'upload',
    '/api/SystemSettings': 'settings', '/api/SystemSettings/EncodingPeriod': 'settings', '/api/SystemSettings/reset-season': 'settings'
};

test('every compatibility route has exactly one owning service', () => {
    for (const [path, service] of Object.entries(expected)) {
        assert.equal(resolveRoute(path), service, path);
        assert.equal(routeDefinitions.filter((definition) => definition.paths.some((pattern) => pattern.test(path))).length, 1, path);
    }
});

test('unknown routes are not forwarded', () => assert.equal(resolveRoute('/api/not-a-real-route'), null));

test('legacy role labels normalize consistently across services', () => {
    assert.equal(normalizeAuthRole('Chairperson'), 'department_admin');
    assert.equal(normalizeAuthRole('Dept Admin'), 'department_admin');
    assert.equal(normalizeAuthRole('System Administrator'), 'system_admin');
    assert.equal(normalizeAuthRole('Instructor'), 'faculty');
});

test('CouchDB transport failures are retried without retrying authentication failures', () => {
    assert.equal(isRetryableCouchDbError({ code: 'ECONNRESET' }), true);
    assert.equal(isRetryableCouchDbError({ statusCode: 503 }), true);
    assert.equal(isRetryableCouchDbError({ statusCode: 401, message: 'unauthorized' }), false);
});
