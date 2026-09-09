const { normalizeAuthRole } = require('./roles');

function normalizeLoginIdentifier(value) {
    return String(value || '').trim().toLowerCase();
}

function canUseLoginIdentifier(account, suppliedIdentifier) {
    if (normalizeAuthRole(account?.role) !== 'student') return true;
    const studentNumber = normalizeLoginIdentifier(account?.student_no);
    return studentNumber.length > 0 && normalizeLoginIdentifier(suppliedIdentifier) === studentNumber;
}

module.exports = { canUseLoginIdentifier, normalizeLoginIdentifier };
