import React, { useMemo, useState } from 'react';
import { getGradeEquivalent } from '../../utils/gradingHelpers';

const yearLabels = { 1: '1st Year', 2: '2nd Year', 3: '3rd Year', 4: '4th Year' };
const semesterOrder = ['1st Semester', 'First Semester', '2nd Semester', 'Second Semester', 'Midyear', 'Summer'];

const displayEquivalent = (grade) => {
  const numericGrade = Number(grade.finalAverage || grade.grade);
  if (!Number.isFinite(numericGrade)) return '—';
  return numericGrade > 5 ? getGradeEquivalent(numericGrade) : numericGrade.toFixed(2);
};

const StudentHistoricalGrades = ({ grades = [], loading = false, error = '', emptyMessage = '' }) => {
  const availableYears = useMemo(() => new Set(grades.map((grade) => Number(grade.yearLevel)).filter(Boolean)), [grades]);
  const [activeYear, setActiveYear] = useState(() => Number([...availableYears][0]) || 1);

  const yearGrades = grades.filter((grade) => Number(grade.yearLevel) === activeYear);
  const semesters = [...new Set(yearGrades.map((grade) => grade.semester || 'Unspecified Semester'))]
    .sort((a, b) => {
      const ai = semesterOrder.findIndex((value) => value.toLowerCase() === String(a).toLowerCase());
      const bi = semesterOrder.findIndex((value) => value.toLowerCase() === String(b).toLowerCase());
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
    });

  if (loading) return <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-slate-500">Loading your finalized grade history…</div>;

  if (error) {
    return (
      <section className="rounded-2xl border border-red-200 bg-white p-4 shadow-sm sm:p-6">
        <h2 className="text-xl font-bold text-[#003366]">My Grades</h2>
        <div role="alert" className="mt-5 rounded-xl border border-red-200 bg-red-50 p-6 text-center text-red-700">{error}</div>
      </section>
    );
  }

  if (grades.length === 0) {
    return (
      <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-6">
        <h2 className="text-xl font-bold text-[#003366]">My Grades</h2>
        
        <div className="mt-5 rounded-xl border border-dashed border-slate-300 p-8 text-center text-slate-500">
          {emptyMessage || 'There are currently no grade records available.'}
        </div>
      </section>
    );
  }

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-6">
      <div className="mb-5">
        <h2 className="text-xl font-bold text-[#003366]">My Grades</h2>
        
      </div>

      <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-4" role="tablist" aria-label="Grade year level">
        {[1, 2, 3, 4].map((year) => (
          <button
            key={year}
            type="button"
            onClick={() => setActiveYear(year)}
            className={`rounded-lg px-3 py-2 text-sm font-semibold transition ${activeYear === year ? 'bg-[#003366] text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
          >
            {yearLabels[year]}{availableYears.has(year) ? '' : ' — No records'}
          </button>
        ))}
      </div>

      {semesters.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-300 p-8 text-center text-slate-500">No finalized grades are available for {yearLabels[activeYear]}.</div>
      ) : semesters.map((semester) => {
        const semesterGrades = yearGrades.filter((grade) => (grade.semester || 'Unspecified Semester') === semester);
        return (
          <div key={semester} className="mb-7 last:mb-0">
            <h3 className="mb-3 text-base font-bold text-slate-800">{semester}</h3>
            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Subject</th><th className="px-4 py-3">Professor</th><th className="px-4 py-3">Units</th>
                    <th className="px-4 py-3">Term</th><th className="px-4 py-3">Grade</th><th className="px-4 py-3">Equivalent</th><th className="px-4 py-3">School Year</th>
                    <th className="px-4 py-3">Status</th><th className="px-4 py-3">Transaction</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {semesterGrades.map((grade, index) => (
                    <tr key={`${grade.recordId}-${grade.term}-${index}`} className="hover:bg-slate-50">
                      <td className="px-4 py-3"><span className="block font-bold text-[#003366]">{grade.subjectCode}</span><span className="text-slate-600">{grade.subjectTitle}</span></td>
                      <td className="px-4 py-3 text-slate-700">{grade.professor || 'Not recorded'}</td>
                      <td className="px-4 py-3">{grade.units || '—'}</td>
                      <td className="px-4 py-3 capitalize">{grade.term}</td>
                      <td className="px-4 py-3 font-bold">{grade.grade || '—'}</td>
                      <td className="px-4 py-3 font-bold text-[#003366]">{displayEquivalent(grade)}</td>
                      <td className="px-4 py-3">{grade.schoolYear || '—'}</td>
                      <td className="px-4 py-3"><span className="rounded-full bg-emerald-100 px-2 py-1 text-xs font-semibold text-emerald-800">{grade.status}</span></td>
                      <td className="max-w-[180px] truncate px-4 py-3 font-mono text-xs" title={grade.transactionHash || grade.transactionId}>{grade.transactionHash || grade.transactionId || 'Legacy record'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </section>
  );
};

export default StudentHistoricalGrades;
