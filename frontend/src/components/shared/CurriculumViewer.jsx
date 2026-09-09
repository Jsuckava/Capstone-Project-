import React, { useEffect, useMemo, useState } from 'react';

const yearLabels = { 1: '1st Year', 2: '2nd Year', 3: '3rd Year', 4: '4th Year' };
const semesterLabels = { FIRST: 'First Semester', SECOND: 'Second Semester', MIDYEAR: 'Summer / Midyear' };

const CurriculumViewer = ({ curricula = [], currentYear = 0, loading = false, emptyMessage = 'No published curriculum is available.' }) => {
  const [selectedId, setSelectedId] = useState('');
  const [activeYear, setActiveYear] = useState(Number(currentYear) || 1);
  useEffect(() => { if (curricula.length && !curricula.some((item) => String(item.curriculumId) === String(selectedId))) setSelectedId(String(curricula[0].curriculumId)); }, [curricula, selectedId]);
  const curriculum = useMemo(() => curricula.find((item) => String(item.curriculumId) === String(selectedId)) || curricula[0], [curricula, selectedId]);

  if (loading) return <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-slate-500">Loading curriculum checklist…</div>;
  if (!curriculum) return <div className="rounded-xl border border-dashed border-slate-300 bg-white p-10 text-center text-slate-500">{emptyMessage}</div>;

  const subjects = Array.isArray(curriculum.subjects) ? curriculum.subjects : [];
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-wide text-blue-700">{curriculum.programCode} · {curriculum.status}</p><h2 className="text-xl font-bold text-[#003366]">{curriculum.curriculumName}</h2><p className="mt-1 text-sm text-slate-500">{curriculum.programName} · Version {curriculum.curriculumVersion}{curriculum.schoolYear ? ` · ${curriculum.schoolYear}` : ''}</p></div>{curricula.length > 1 ? <select value={selectedId} onChange={(event) => setSelectedId(event.target.value)} className="rounded-lg border border-slate-300 px-3 py-2 text-sm">{curricula.map((item) => <option key={item.curriculumId} value={item.curriculumId}>{item.programCode} — {item.curriculumVersion}</option>)}</select> : null}</div>
      {curriculum.submittedAt ? <p className="mb-4 text-xs text-slate-500">Submitted for approval: {new Date(curriculum.submittedAt).toLocaleString()}</p> : null}
      <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-4">{[1, 2, 3, 4].map((year) => <button key={year} type="button" onClick={() => setActiveYear(year)} className={`rounded-lg px-3 py-2 text-sm font-semibold ${activeYear === year ? 'bg-[#003366] text-white' : Number(currentYear) === year ? 'bg-yellow-100 text-yellow-900 ring-1 ring-yellow-300' : 'bg-slate-100 text-slate-700'}`}>{yearLabels[year]}{Number(currentYear) === year ? ' · Current' : ''}</button>)}</div>
      {['FIRST', 'SECOND', 'MIDYEAR'].map((semester) => {
        const rows = subjects.filter((subject) => Number(subject.yearLevel) === activeYear && subject.semester === semester);
        if (semester === 'MIDYEAR' && rows.length === 0) return null;
        const total = rows.reduce((sum, subject) => sum + Number(subject.units || 0), 0);
        return <div key={semester} className="mb-7 last:mb-0"><div className="mb-2 flex items-center justify-between"><h3 className="font-bold text-slate-800">{semesterLabels[semester]}</h3><span className="text-sm font-semibold text-slate-600">Total Units: {total}</span></div><div className="overflow-x-auto rounded-xl border border-slate-200"><table className="min-w-full divide-y divide-slate-200 text-sm"><thead className="bg-slate-50 text-left text-xs uppercase text-slate-500"><tr><th className="px-4 py-3">Code</th><th className="px-4 py-3">Subject</th><th className="px-4 py-3">Units</th><th className="px-4 py-3">Lecture</th><th className="px-4 py-3">Laboratory</th><th className="px-4 py-3">Prerequisite</th><th className="px-4 py-3">Category</th></tr></thead><tbody className="divide-y divide-slate-100">{rows.length ? rows.map((subject) => <tr key={subject.subjectId}><td className="px-4 py-3 font-bold text-[#003366]">{subject.subjectCode}</td><td className="px-4 py-3">{subject.subjectTitle}</td><td className="px-4 py-3">{subject.units}</td><td className="px-4 py-3">{subject.lectureHours}</td><td className="px-4 py-3">{subject.laboratoryHours}</td><td className="px-4 py-3">{subject.prerequisite || 'None'}</td><td className="px-4 py-3">{subject.subjectType || '—'}</td></tr>) : <tr><td colSpan="7" className="px-4 py-7 text-center text-slate-400">No subjects configured.</td></tr>}</tbody></table></div></div>;
      })}
      <div className="mt-4 flex justify-end border-t border-slate-200 pt-4 text-sm font-bold text-[#003366]">Overall Curriculum Units: {curriculum.totalUnits ?? subjects.reduce((sum, subject) => sum + Number(subject.units || 0), 0)}</div>
    </section>
  );
};

export default CurriculumViewer;
