import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import StudentEnrollmentManagement from './StudentEnrollmentManagement';
import {
  fetchApprovedStudents,
  fetchCurriculums,
  registrarBulkEnrollStudents,
} from '../../services/api';

jest.mock('../../services/api', () => ({
  fetchApprovedStudents: jest.fn(),
  fetchCurriculums: jest.fn(),
  registrarBulkEnrollStudents: jest.fn(),
  registrarBulkUpdateStudents: jest.fn(),
}));

const program = 'Bachelor of Science in Information Technology';

beforeEach(() => {
  jest.clearAllMocks();
  fetchApprovedStudents.mockResolvedValue({
    status: 'Success',
    students: [{
      id: 42,
      fullname: 'Juan Dela Cruz',
      studentno: '26-0001',
      department: program,
      yearLevel: '1',
      section: '1-1',
      schoolYear: '2026-2027',
      semester: 'FIRST',
      curriculumVersion: 'BSIT-2026',
      enrollmentStatus: 'ENROLLED',
    }],
  });
  fetchCurriculums.mockResolvedValue({
    status: 'Success',
    data: [{
      curriculumId: 7,
      curriculumName: 'BSIT Curriculum 2026',
      curriculumVersion: 'BSIT-2026',
      programName: program,
      programCode: 'BSIT',
    }],
  });
  registrarBulkEnrollStudents.mockResolvedValue({ status: 'Success', message: 'Student enrollment saved.' });
});

test('manually enrolls a student in the selected academic period and curriculum', async () => {
  render(<StudentEnrollmentManagement programs={[program]} />);

  await screen.findByText('Juan Dela Cruz');
  await waitFor(() => expect(screen.getByLabelText(/curriculum version/i)).toHaveValue('7'));

  fireEvent.change(screen.getByLabelText(/school year/i), { target: { value: '2026-2027' } });
  fireEvent.change(screen.getByLabelText(/^semester/i), { target: { value: 'SECOND' } });
  fireEvent.change(screen.getByLabelText(/^year level/i), { target: { value: '2' } });
  fireEvent.click(screen.getByRole('button', { name: /manual entry/i }));
  fireEvent.change(screen.getByLabelText(/first name/i), { target: { value: 'Maria' } });
  fireEvent.change(screen.getByLabelText(/last name/i), { target: { value: 'Santos' } });
  fireEvent.change(screen.getByLabelText(/birthdate/i), { target: { value: '2006-02-28' } });
  fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'maria.santos@plv.edu.ph' } });
  fireEvent.change(screen.getByLabelText(/contact number/i), { target: { value: '09123456789' } });
  fireEvent.change(screen.getByLabelText(/home address/i), { target: { value: 'Valenzuela City' } });
  fireEvent.click(screen.getByRole('button', { name: /save student/i }));

  await waitFor(() => expect(registrarBulkEnrollStudents).toHaveBeenCalled());
  const [file, department, context] = registrarBulkEnrollStudents.mock.calls[0];
  expect(file).toBeInstanceOf(File);
  expect(file.name).toBe('manual-student-enrollment.csv');
  expect(department).toBe(program);
  expect(context).toEqual({
    curriculumId: '7',
    schoolYear: '2026-2027',
    yearLevel: '2',
    semester: 'SECOND',
  });
});
