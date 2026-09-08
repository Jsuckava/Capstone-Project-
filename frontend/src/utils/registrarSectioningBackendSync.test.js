import { syncSectioningBatchToBackend } from './registrarSectioningBackendSync';
import { assignStudentsToSection, batchEnrollStudentsToSection, createSection, fetchDepartmentSections } from '../services/api';

jest.mock('../services/api', () => ({
  assignStudentsToSection: jest.fn(),
  batchEnrollStudentsToSection: jest.fn(),
  createSection: jest.fn(),
  fetchDepartmentSections: jest.fn(),
}));

const batch = {
  program: 'BSIT', schoolYear: '2026-2027', semester: 'SECOND',
  sectionPlans: [{ yearLevel: '1st Year', sectionCode: '1-1' }],
  students: [{ studentId: '26-0001', yearLevel: '1st Year', sectionCode: '1-1' }],
};

beforeEach(() => {
  jest.clearAllMocks();
  fetchDepartmentSections.mockResolvedValue({ data: [{ id: '7', department: 'Information Technology', yearLevel: '1', sectionNum: '1' }] });
  createSection.mockResolvedValue({ id: 8 });
  assignStudentsToSection.mockResolvedValue({ status: 'Success', assignedCount: 1, errors: [] });
});

test('uses an existing section returned for a program alias and assigns saved student IDs with their period', async () => {
  expect(await syncSectioningBatchToBackend(batch)).toEqual({ sectionsSynced: 0, studentsSynced: 1 });
  expect(createSection).not.toHaveBeenCalled();
  expect(assignStudentsToSection).toHaveBeenCalledWith('7', ['26-0001'], { schoolYear: '2026-2027', semester: 'SECOND' });
  expect(batchEnrollStudentsToSection).not.toHaveBeenCalled();
});

test('creates a section and assigns its enrolled roster without a file upload', async () => {
  fetchDepartmentSections.mockResolvedValue({ data: [] });
  expect(await syncSectioningBatchToBackend(batch)).toEqual({ sectionsSynced: 1, studentsSynced: 1 });
  expect(assignStudentsToSection).toHaveBeenCalledWith(8, ['26-0001'], expect.any(Object));
  expect(batchEnrollStudentsToSection).not.toHaveBeenCalled();
});

test('surfaces assignment errors without re-enrolling students', async () => {
  assignStudentsToSection.mockRejectedValue(new Error('Student already assigned'));
  await expect(syncSectioningBatchToBackend(batch)).rejects.toThrow('Student already assigned');
  expect(batchEnrollStudentsToSection).not.toHaveBeenCalled();
});

test('rejects partial success from an older backend', async () => {
  assignStudentsToSection.mockResolvedValue({ status: 'Success', assignedCount: 0, errors: ['No eligible enrollment'] });
  await expect(syncSectioningBatchToBackend(batch)).rejects.toThrow('No eligible enrollment');
  expect(batchEnrollStudentsToSection).not.toHaveBeenCalled();
});

test('requires the enrollment period instead of silently choosing a different period', async () => {
  await expect(syncSectioningBatchToBackend({ ...batch, semester: undefined })).rejects.toThrow('school year and semester');
  expect(assignStudentsToSection).not.toHaveBeenCalled();
});
