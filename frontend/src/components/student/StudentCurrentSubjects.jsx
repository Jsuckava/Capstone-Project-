import React, { useMemo, useState } from 'react';
import { getGradeEquivalent } from '../../utils/gradingHelpers';

const normalizeSemester = (value = '') => String(value).toUpperCase().replace(/[^A-Z0-9]/g, '');
const displayGrade = (record) => record?.finalAverage || record?.grade || 'Not yet available';
const displayEquivalent = (record) => {
  const numeric = Number(record?.finalAverage || record?.grade);
  if (!Number.isFinite(numeric)) return '—';
  return numeric > 5 ? getGradeEquivalent(numeric) : numeric.toFixed(2);
};

function StudentCurrentSubjects({ grades = [], schoolYear = '', semester = '', loading = false, error = '' }) {
  const [openSubject, setOpenSubject] = useState('');
  const subjects = useMemo(() => {
    const current = grades.filter((grade) =>
      (!schoolYear || grade.schoolYear === schoolYear) &&
      (!semester || normalizeSemester(grade.semester) === normalizeSemester(semester))
    );
    const grouped = new Map();
    current.forEach((grade) => {
      const key = grade.subjectCode || grade.recordId;
      const existing = grouped.get(key) || { ...grade, terms: [] };
      existing.terms.push(grade);
      if (String(grade.term).toLowerCase() === 'finals') Object.assign(existing, grade);
      grouped.set(key, existing);
    });
    return [...grouped.values()].sort((a, b) => String(a.subjectCode).localeCompare(String(b.subjectCode)));
  }, [grades, schoolYear, semester]);

  if (loading) return <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-slate-500">Loading current subjects…</div>;

  return (
    <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 px-5 py-4">
        <p className="text-xs font-bold uppercase tracking-wide text-slate-500">{schoolYear || 'Current school year'} · {semester || 'Current semester'}</p>
        <h2 className="mt-1 text-xl font-bold text-[#003366]">Current Subjects</h2>
        <p className="mt-1 text-sm text-slate-500">Select a subject to view its finalized grade, professor, and ledger reference.</p>
      </div>
      {error ? <div role="alert" className="m-4 rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      {!error && subjects.length === 0 ? <div className="m-4 rounded-xl border border-dashed border-slate-300 p-8 text-center text-slate-500">No finalized subjects are available for the current semester.</div> : null}
      <div className="divide-y divide-slate-100">
        {subjects.map((subject) => {
          const key = subject.subjectCode || subject.recordId;
          const expanded = openSubject === key;
          const transaction = subject.transactionHash || subject.transactionId;
          return <article key={key}>
            <button type="button" onClick={() => setOpenSubject(expanded ? '' : key)} className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left hover:bg-slate-50" aria-expanded={expanded}>
              <span><span className="block font-bold text-[#003366]">{subject.subjectCode || 'Subject'}</span><span className="text-sm text-slate-600">{subject.subjectTitle || 'Untitled subject'}</span></span>
              <span className="flex items-center gap-3"><span className="hidden rounded-full bg-blue-50 px-3 py-1 text-xs font-semibold text-blue-700 sm:inline">{subject.units || 0} units</span><span className={`text-xl text-slate-500 transition ${expanded ? 'rotate-180' : ''}`}>⌄</span></span>
            </button>
            {expanded ? <div className="grid gap-3 bg-slate-50 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-lg border border-slate-200 bg-white p-3"><p className="text-xs text-slate-500">Finalized Grade</p><p className="mt-1 font-bold text-[#003366]">{displayGrade(subject)} <span className="text-xs font-normal text-slate-500">({displayEquivalent(subject)})</span></p></div>
              <div className="rounded-lg border border-slate-200 bg-white p-3"><p className="text-xs text-slate-500">Professor</p><p className="mt-1 font-semibold">{subject.professor || 'Not recorded'}</p></div>
              <div className="rounded-lg border border-slate-200 bg-white p-3"><p className="text-xs text-slate-500">Committed by</p><p className="mt-1 font-semibold">{subject.committedBy || subject.professor || subject.facultyId || 'Not recorded'}</p></div>
              <div className="rounded-lg border border-slate-200 bg-white p-3"><p className="text-xs text-slate-500">Blockchain transaction</p><p className="mt-1 break-all font-mono text-xs">{transaction || 'Legacy record'}</p></div>
            </div> : null}
          </article>;
        })}
      </div>
    </section>
  );
}

export default StudentCurrentSubjects;
