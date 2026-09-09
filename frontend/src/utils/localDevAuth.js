const LOCAL_DEV_ACCOUNTS = {
  student: {
    aliases: ['student', 'student@plv.edu.ph'],
    email: 'student@plv.edu.ph',
    name: 'Juan Dela Cruz',
    role: 'student',
    studentNo: '23-0001',
    middleName: '',
    sex: 'Male',
    phone: 'N/A',
    address: 'Valenzuela City',
    department: 'College of Information Technology and Engineering',
    section: 'BSIT 1-1',
    yearLevel: '1st Year',
    enrollmentStatus: 'Enrolled',
    enrolledSubjects: [],
  },
  faculty: {
    aliases: ['faculty', 'faculty@plv.edu.ph'],
    email: 'faculty@plv.edu.ph',
    name: 'Local Faculty',
    role: 'faculty',
    department: 'College of Information Technology and Engineering',
    facultyType: 'Full Time',
  },
  department_admin: {
    aliases: ['chairperson', 'chairperson@plv.edu.ph', 'department_admin'],
    email: 'chairperson@plv.edu.ph',
    name: 'Local Chairperson',
    role: 'department_admin',
    department: 'College of Information Technology and Engineering',
  },
  registrar: {
    aliases: ['registrar', 'registrar@plv.edu.ph', 'registrar@gmail.com'],
    email: 'registrar@plv.edu.ph',
    name: 'PLV Registrar',
    role: 'registrar',
  },
  system_admin: {
    aliases: [
      'admin',
      'systemadmin',
      'system_admin',
      'system-admin',
      'admin@plv.edu.ph',
      'sysadmin@plv.edu.ph',
      'system.admin@plv.edu.ph',
      'systemadmin@plv.edu.ph',
    ],
    email: 'systemadmin@plv.edu.ph',
    name: 'System Administrator',
    role: 'system_admin',
  },
};

const encodeJwtPart = (value) =>
  window.btoa(JSON.stringify(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const createTokenForAccount = (account) => {
  if (!account) return null;

  const payload = {
    ...account,
    aliases: undefined,
    localDevAuth: true,
    email: account.email,
    username: account.email,
    name: account.name,
    role: account.role,
  };

  return `${encodeJwtPart({ alg: 'none', typ: 'JWT' })}.${encodeJwtPart(payload)}.local-dev`;
};

export const createLocalDevTokenForRole = (role) => {
  if (process.env.NODE_ENV !== 'development') return null;
  return createTokenForAccount(LOCAL_DEV_ACCOUNTS[role]);
};

export const createLocalDevToken = (username) => {
  if (process.env.NODE_ENV !== 'development') return null;

  const normalizedUsername = String(username || '').trim().toLowerCase();
  const account = Object.values(LOCAL_DEV_ACCOUNTS).find(({ aliases }) =>
    aliases.includes(normalizedUsername)
  );

  return createTokenForAccount(account);
};

export const getLocalDevUser = (payload) => {
  if (process.env.NODE_ENV !== 'development' || payload?.localDevAuth !== true) return null;

  const supportedRoles = ['student', 'faculty', 'department_admin', 'registrar', 'system_admin'];
  if (!supportedRoles.includes(payload.role)) return null;

  const role = payload.role;
  return {
    ...payload,
    id: `local-${role}`,
    name: payload.name || 'Local User',
    email: payload.email,
    role,
    rawRole: role,
    status: 'Active',
  };
};
