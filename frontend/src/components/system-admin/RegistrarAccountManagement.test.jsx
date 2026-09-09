import { render, screen, waitFor } from '@testing-library/react';
import RegistrarAccountManagement from './RegistrarAccountManagement';
import { fetchRegistrarAccounts } from '../../services/api';

jest.mock('../../services/api', () => ({
  createRegistrarAccount: jest.fn(),
  deleteRegistrarAccount: jest.fn(),
  fetchRegistrarAccounts: jest.fn(),
  resetManagedAccountPassword: jest.fn(),
  updateRegistrarAccount: jest.fn(),
}));

const registrar = (id) => ({
  id,
  registrarId: `REG-${id}`,
  accountId: `REG-${id}`,
  fullName: `Registrar ${id}`,
  email: `registrar${id}@plv.edu.ph`,
  isActive: true,
});

test('hides Registrar creation after the two-account limit is reached', async () => {
  fetchRegistrarAccounts.mockResolvedValue({ data: [registrar(1), registrar(2)] });
  render(<RegistrarAccountManagement />);

  await waitFor(() => expect(screen.getByText('2 / 2 Registrar accounts')).toBeInTheDocument());
  expect(screen.queryByRole('button', { name: 'Create Registrar' })).not.toBeInTheDocument();
  expect(screen.getByText(/two-Registrar limit has been reached/i)).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Delete Registrar' })).toHaveLength(2);
});

test('shows Registrar creation while a slot is available', async () => {
  fetchRegistrarAccounts.mockResolvedValue({ data: [registrar(1)] });
  render(<RegistrarAccountManagement />);

  await waitFor(() => expect(screen.getByText('1 / 2 Registrar accounts')).toBeInTheDocument());
  expect(screen.getByRole('button', { name: 'Create Registrar' })).toBeInTheDocument();
});
