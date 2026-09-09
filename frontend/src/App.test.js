import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';
import { fetchUserProfile, login } from './services/api';

jest.mock('./services/api', () => ({
  ...jest.requireActual('./services/api'),
  fetchUserProfile: jest.fn(),
  login: jest.fn(),
}));

jest.mock('./services/nginxFailover', () => ({
  startNginxFailoverMonitor: jest.fn(() => () => {}),
}));

jest.mock('./components/shared/Chat', () => () => null);

jest.mock('./components/faculty/FacultyPortal', () => ({ facultyData }) => (
  <main>Faculty Portal for {facultyData.email}</main>
));

const tokenFor = (role, username) => {
  const encode = (value) => btoa(JSON.stringify(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${encode({ alg: 'none' })}.${encode({ dbRole: role, username })}.signature`;
};

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  window.history.replaceState({}, '', '/');
  jest.clearAllMocks();
});

test('keeps the signed-in account in sessionStorage and shows its role URL', async () => {
  const token = tokenFor('faculty', 'faculty@plv.edu.ph');
  login.mockResolvedValue({ token });
  fetchUserProfile.mockResolvedValue({
    status: 'Success',
    data: { id: 7, email: 'faculty@plv.edu.ph', fullName: 'Test Faculty', role: 'faculty', status: 'APPROVED' },
  });
  window.history.replaceState({}, '', '/login');

  render(<App />);
  fireEvent.change(await screen.findByPlaceholderText(/example@plv.edu.ph/i), { target: { value: 'faculty@plv.edu.ph' } });
  fireEvent.change(screen.getByPlaceholderText(/^password$/i), { target: { value: 'Password1!' } });
  fireEvent.click(screen.getByRole('button', { name: /^sign in$/i }));

  await waitFor(() => expect(window.location.pathname).toBe('/faculty'));
  expect(screen.queryByRole('button', { name: /new login tab/i })).not.toBeInTheDocument();
  expect(sessionStorage.getItem('blockgo.auth.token')).toBe(token);
  expect(localStorage.getItem('token')).toBeNull();
});

test('renders managed-account login at the stable login route without public registration', async () => {
  render(<App />);
  expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument();
  expect(window.location.pathname).toBe('/login');
  expect(screen.getByText(/forgot password/i)).toBeInTheDocument();
  expect(screen.queryByText(/each browser tab keeps an independent account session/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/sign up|register|create account/i)).not.toBeInTheDocument();
});
