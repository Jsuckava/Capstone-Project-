import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import StudentBlockchainTransactions from './StudentBlockchainTransactions';
import { fetchStudentBlockchainTransactions } from '../../services/api';

jest.mock('../../services/api', () => ({
  fetchStudentBlockchainTransactions: jest.fn(),
}));

beforeEach(() => {
  fetchStudentBlockchainTransactions.mockResolvedValue({
    status: 'Success',
    data: Array.from({ length: 12 }, (_, index) => ({
      transactionId: `transaction-${index + 1}`,
      transactionHash: `hash-${index + 1}-abcdefghijklmnopqrstuvwxyz`,
      transactionType: 'GRADE_FINALIZED',
      studentId: `26-${String(index + 1).padStart(4, '0')}`,
      subjectCode: `TEST-${index + 1}`,
      subjectTitle: `Test Subject ${index + 1}`,
      professor: 'Test Faculty',
      semester: '1st Semester',
      schoolYear: '2026-2027',
      term: 'midterm',
      grade: '90',
      status: 'Finalized',
      timestamp: new Date(Date.UTC(2026, 0, index + 1)).toISOString(),
    })),
  });
});

test('shows ten student blockchain transactions per page and navigates to the remainder', async () => {
  render(<StudentBlockchainTransactions />);

  expect(await screen.findByText('TEST-1')).toBeInTheDocument();
  expect(screen.getByText('TEST-10')).toBeInTheDocument();
  expect(screen.queryByText('TEST-11')).not.toBeInTheDocument();
  expect(screen.getByText(/Page 1 of 2/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Next' }));

  expect(await screen.findByText('TEST-11')).toBeInTheDocument();
  expect(screen.getByText('TEST-12')).toBeInTheDocument();
  expect(screen.queryByText('TEST-1')).not.toBeInTheDocument();
  expect(screen.getByText(/Page 2 of 2/)).toBeInTheDocument();
});
