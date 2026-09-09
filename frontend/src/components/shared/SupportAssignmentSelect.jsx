import React from 'react';

export const assignmentPayload = (value) => {
  if (String(value).startsWith('specialty:')) {
    return { assignedSpecialist: String(value).slice('specialty:'.length) };
  }
  return null;
};

export const assignmentValueForTicket = (ticket) => {
  if (ticket?.assignedSpecialist) return `specialty:${ticket.assignedSpecialist}`;
  return '';
};

const SupportAssignmentSelect = ({ value, onChange, specialists = [], className = '', ariaLabel }) => (
  <select required value={value} onChange={(event) => onChange(event.target.value)} className={className} aria-label={ariaLabel}>
    <option value="">Select support specialist</option>
    {specialists.map((specialist) => (
      <option key={specialist.specialistId} value={`specialty:${specialist.specialistId}`}>
        {specialist.label} - {specialist.scope}
      </option>
    ))}
  </select>
);

export default SupportAssignmentSelect;
