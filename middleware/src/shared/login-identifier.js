const { normalizeAuthRole } = require('./roles');

function normalizeLoginIdentifier(value) {
    return String(value || '').trim().toLowerCase();
}

function canUseLoginIdentifier(account, suppliedIdentifier) {
    if (normalizeAuthRole(account?.role) !== 'student') return true;
    const supplied = normalizeLoginIdentifier(suppliedIdentifier);
    const studentNumber = normalizeLoginIdentifier(account?.student_no);
    const email = normalizeLoginIdentifier(account?.email);
    return (studentNumber.length > 0 && supplied === studentNumber) ||
        (email.length > 0 && supplied === email);
}

module.exports = { canUseLoginIdentifier, normalizeLoginIdentifier };
