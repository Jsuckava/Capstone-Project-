function normalizeAuthRole(role) {
    const normalized = String(role || '').toLowerCase().trim().replace(/[\s-]+/g, '_');
    if (['system_admin', 'systemadmin', 'system_administrator', 'sysadmin'].includes(normalized)) return 'system_admin';
    if (['department_admin', 'departmentadmin', 'dept_admin', 'deptadmin', 'department', 'chairperson', 'department_head', 'admin'].includes(normalized)) return 'department_admin';
    if (['faculty', 'instructor'].includes(normalized)) return 'faculty';
    if (normalized === 'registrar') return 'registrar';
    if (normalized === 'student') return 'student';
    return normalized;
}

module.exports = { normalizeAuthRole };
