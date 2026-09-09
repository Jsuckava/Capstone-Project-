const { normalizeAuthRole } = require('./roles');

function sourceForRecord(record) {
    const status = String(record?.status || record?.Status || '').trim().toLowerCase();
    if (status === 'finalized') return 'registrar';
    if (['departmentapproved', 'approved'].includes(status)) return 'department_admin';
    if (status === 'returned') return 'academic_review';
    return 'faculty';
}

function projectLedgerTransaction(record) {
    const source = sourceForRecord(record);
    const transactionId = record.transaction_id || record.transactionId || record.TransactionId || '';
    return {
        recordId: record.id || record.Id || '',
        transactionId,
        transactionHash: record.transaction_hash || record.transactionHash || record.TransactionHash || transactionId,
        source,
        actorRole: source,
        actor: source === 'registrar'
            ? 'Registrar'
            : (record.submitted_by || record.submittedBy || record.faculty_id || record.facultyId || source),
        submittedBy: record.submitted_by || record.submittedBy || '',
        studentId: record.student_no || record.studentNo || record.student_id || record.studentId || '',
        studentName: record.student_name || record.studentName || '',
        subjectCode: record.subject_code || record.subjectCode || '',
        subjectTitle: record.subject_title || record.subjectTitle || '',
        program: record.program || record.course || '',
        section: record.section || '',
        semester: record.semester || '',
        schoolYear: record.school_year || record.schoolYear || '',
        status: record.status || record.Status || '',
        occurredAt: record.timestamp || record.recorded_at || record.recordedAt || record.date || ''
    };
}

function filterLedgerTransactions(records, filters = {}) {
    const requestedSource = filters.source ? normalizeAuthRole(filters.source) : '';
    const search = String(filters.search || '').trim().toLowerCase();
    const schoolYear = String(filters.schoolYear || '').trim().toLowerCase();
    const semester = String(filters.semester || '').trim().toLowerCase();
    const from = filters.from ? new Date(filters.from) : null;
    const to = filters.to ? new Date(filters.to) : null;
    const limit = Math.min(500, Math.max(1, Number.parseInt(filters.limit, 10) || 100));

    return (Array.isArray(records) ? records : [])
        .map(projectLedgerTransaction)
        .filter((item) => !requestedSource || normalizeAuthRole(item.source) === requestedSource)
        .filter((item) => !schoolYear || item.schoolYear.toLowerCase() === schoolYear)
        .filter((item) => !semester || item.semester.toLowerCase() === semester)
        .filter((item) => !search || [item.recordId, item.transactionId, item.transactionHash, item.studentId,
            item.studentName, item.subjectCode, item.actor, item.submittedBy]
            .some((value) => String(value || '').toLowerCase().includes(search)))
        .filter((item) => {
            if (!from && !to) return true;
            const occurredAt = new Date(item.occurredAt);
            if (Number.isNaN(occurredAt.getTime())) return false;
            if (from && occurredAt < from) return false;
            if (to) {
                const inclusiveTo = new Date(to);
                inclusiveTo.setUTCDate(inclusiveTo.getUTCDate() + 1);
                if (occurredAt >= inclusiveTo) return false;
            }
            return true;
        })
        .sort((left, right) => new Date(right.occurredAt || 0) - new Date(left.occurredAt || 0))
        .slice(0, limit);
}

module.exports = { filterLedgerTransactions, projectLedgerTransaction, sourceForRecord };
