const SESSION_TOKEN_KEY = 'blockgo.auth.token';
const SESSION_ROLE_KEY = 'blockgo.auth.role';
const LEGACY_TOKEN_KEY = 'token';
const LEGACY_ROLE_KEY = 'userRole';

const ROLE_ROUTES = Object.freeze({
  system_admin: '/system-admin',
  registrar: '/registrar',
  department_admin: '/department-admin',
  faculty: '/faculty',
  student: '/student',
});

export const normalizeSessionRole = (role) => {
  const normalized = String(role || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (['system_admin', 'systemadmin', 'system_administrator', 'systemadministrator'].includes(normalized)) return 'system_admin';
  if (['dept_admin', 'deptadmin', 'department_admin', 'departmentadmin', 'department', 'chairperson', 'department_head', 'admin', 'departmentmsp'].includes(normalized)) return 'department_admin';
  if (normalized === 'facultymsp') return 'faculty';
  if (normalized === 'registrarmsp') return 'registrar';
  return normalized;
};

export const decodeAuthToken = (token) => {
  const encodedPayload = String(token || '').split('.')[1];
  if (!encodedPayload) throw new Error('Invalid authentication token.');
  const normalizedPayload = encodedPayload.replace(/-/g, '+').replace(/_/g, '/');
  const paddedPayload = normalizedPayload.padEnd(Math.ceil(normalizedPayload.length / 4) * 4, '=');
  return JSON.parse(atob(paddedPayload));
};

export const roleFromToken = (token) => {
  const payload = decodeAuthToken(token);
  return normalizeSessionRole(
    payload.dbRole || payload.role || payload['http://schemas.microsoft.com/ws/2008/06/identity/claims/role']
  );
};

export const routeForRole = (role) => ROLE_ROUTES[normalizeSessionRole(role)] || '/login';

export const roleForRoute = (pathname) => {
  const normalizedPath = `/${String(pathname || '').split('?')[0].split('#')[0].replace(/^\/+|\/+$/g, '')}`;
  if (normalizedPath === '/dept-admin') return 'department_admin';
  return Object.entries(ROLE_ROUTES).find(([, route]) => route === normalizedPath)?.[0] || null;
};

export const getAuthToken = () => sessionStorage.getItem(SESSION_TOKEN_KEY);

export const setAuthSession = (token, role) => {
  sessionStorage.setItem(SESSION_TOKEN_KEY, token);
  sessionStorage.setItem(SESSION_ROLE_KEY, normalizeSessionRole(role));
  localStorage.removeItem(LEGACY_TOKEN_KEY);
  localStorage.removeItem(LEGACY_ROLE_KEY);
};

export const clearAuthSession = () => {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
  sessionStorage.removeItem(SESSION_ROLE_KEY);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
  localStorage.removeItem(LEGACY_ROLE_KEY);
};

export const migrateLegacyAuthSession = () => {
  const currentToken = getAuthToken();
  if (currentToken) return currentToken;

  const legacyToken = localStorage.getItem(LEGACY_TOKEN_KEY);
  if (!legacyToken) return null;

  setAuthSession(legacyToken, roleFromToken(legacyToken));
  return legacyToken;
};
