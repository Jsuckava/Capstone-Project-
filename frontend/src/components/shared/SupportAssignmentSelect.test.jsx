import { render, screen } from '@testing-library/react';
import { assignmentPayload, assignmentValueForTicket } from './SupportAssignmentSelect';
import SupportAssignmentSelect from './SupportAssignmentSelect';

test('routes a ticket directly to one of the four specialties', () => {
  expect(assignmentPayload('specialty:NETWORK_SPECIALIST')).toEqual({
    assignedSpecialist: 'NETWORK_SPECIALIST',
  });
});

test('rejects named personnel values', () => {
  expect(assignmentPayload('personnel:7')).toBeNull();
});

test('restores an existing specialty assignment in the dropdown', () => {
  expect(assignmentValueForTicket({ assignedSpecialist: 'BACKEND_DEVELOPER' })).toBe('specialty:BACKEND_DEVELOPER');
});

test('shows only the four approved support choices', () => {
  const specialists = [
    { specialistId: 'IT_ADMIN', label: 'IT Admin', scope: 'Overall' },
    { specialistId: 'FRONTEND_DEVELOPER', label: 'Web Developer', scope: 'Frontend' },
    { specialistId: 'BACKEND_DEVELOPER', label: 'API Issues', scope: 'Backend Developer' },
    { specialistId: 'NETWORK_SPECIALIST', label: 'Network and Docker Issues', scope: 'Network Specialist' },
  ];
  render(<SupportAssignmentSelect value="" onChange={() => {}} specialists={specialists} ariaLabel="Support destination" />);

  expect(screen.getAllByRole('option')).toHaveLength(5);
  expect(screen.getByRole('option', { name: 'IT Admin - Overall' })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: 'Web Developer - Frontend' })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: 'API Issues - Backend Developer' })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: 'Network and Docker Issues - Network Specialist' })).toBeInTheDocument();
});
