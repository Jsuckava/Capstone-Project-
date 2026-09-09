import {
  clearAuthSession,
  decodeAuthToken,
  getAuthToken,
  migrateLegacyAuthSession,
  normalizeSessionRole,
  roleForRoute,
  routeForRole,
  setAuthSession,
} from './authSession';

const tokenFor = (role, username = `${role}@plv.edu.ph`) => {
  const encode = (value) => btoa(JSON.stringify(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${encode({ alg: 'none' })}.${encode({ dbRole: role, username })}.signature`;
};

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});

test.each([
  ['registrar', '/registrar'],
  ['department_admin', '/department-admin'],
  ['faculty', '/faculty'],
  ['student', '/student'],
  ['system_admin', '/system-admin'],
])('maps %s sessions to %s', (role, route) => {
  expect(routeForRole(role)).toBe(route);
  expect(roleForRoute(route)).toBe(role);
});

test('normalizes department role aliases', () => {
  expect(normalizeSessionRole('Dept Admin')).toBe('department_admin');
  expect(roleForRoute('/dept-admin')).toBe('department_admin');
});

test('stores authentication only in this tab session', () => {
  const token = tokenFor('faculty');
  setAuthSession(token, 'faculty');
  expect(getAuthToken()).toBe(token);
  expect(localStorage.getItem('token')).toBeNull();
  clearAuthSession();
  expect(getAuthToken()).toBeNull();
});

test('migrates and removes a legacy shared token', () => {
  const token = tokenFor('registrar');
  localStorage.setItem('token', token);
  expect(migrateLegacyAuthSession()).toBe(token);
  expect(getAuthToken()).toBe(token);
  expect(localStorage.getItem('token')).toBeNull();
  expect(decodeAuthToken(token).dbRole).toBe('registrar');
});
