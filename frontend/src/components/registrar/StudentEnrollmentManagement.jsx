import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  fetchApprovedStudents,
  fetchCurriculums,
  registrarBulkEnrollStudents,
  registrarBulkUpdateStudents,
} from '../../services/api';
import { buildCsvContent, downloadCsvFile } from '../../utils/studentSectioningHelpers';
import { downloadTemplateButtonClass } from '../shared/downloadButtonStyles';

const currentSchoolYear = () => {
  const now = new Date();
  const start = now.getMonth() >= 5 ? now.getFullYear() : now.getFullYear() - 1;
  return `${start}-${start + 1}`;
};

const StudentEnrollmentManagement = ({ programs = [] }) => {
  const [form, setForm] = useState({
    department: programs[0] || '',
    schoolYear: currentSchoolYear(),
    semester: new Date().getMonth() >= 5 ? 'FIRST' : 'SECOND',
    yearLevel: '1',
    curriculumId: '',
  });
  const [file, setFile] = useState(null);
  const [students, setStudents] = useState([]);
  const [curricula, setCurricula] = useState([]);
  const [manualForm, setManualForm] = useState({ firstName: '', lastName: '', middleName: '', birthdate: '', email: '', contactNumber: '', homeAddress: '' });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState(null);
  const [enrollmentSearch, setEnrollmentSearch] = useState('');
  const [enrollmentMethod, setEnrollmentMethod] = useState('bulk');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [studentsResponse, curriculumResponse] = await Promise.all([
        fetchApprovedStudents(),
        fetchCurriculums('PUBLISHED'),
      ]);
      setStudents(studentsResponse?.students || studentsResponse?.data || []);
      setCurricula(curriculumResponse?.data || []);
    } catch (error) {
      setResult({ status: 'Error', message: error.message || 'Enrollment data could not be loaded.' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const matchingCurricula = useMemo(
    () => curricula.filter((curriculum) =>
      [curriculum.programName, curriculum.programCode]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase() === String(form.department).toLowerCase())
    ),
    [curricula, form.department]
  );
  const visibleStudents = useMemo(() => {
    const query = enrollmentSearch.trim().toLowerCase();
    if (!query) return students;
    return students.filter((student) =>
      [student.fullname, student.studentno, student.email, student.department]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    );
  }, [students, enrollmentSearch]);

  useEffect(() => {
    if (matchingCurricula.some((item) => String(item.curriculumId) === String(form.curriculumId))) return;
    setForm((current) => ({
      ...current,
      curriculumId: matchingCurricula[0]?.curriculumId ? String(matchingCurricula[0].curriculumId) : '',
    }));
  }, [matchingCurricula, form.curriculumId]);

  const updateField = (field, value) => setForm((current) => ({ ...current, [field]: value }));

  const validateContext = () => {
    if (!form.department) return 'Select an academic program.';
    if (!/^\d{4}-\d{4}$/.test(form.schoolYear)) return 'School year must use YYYY-YYYY.';
    const [start, end] = form.schoolYear.split('-').map(Number);
    if (end !== start + 1) return 'School year must contain consecutive years.';
    if (!/^[1-4]$/.test(form.yearLevel)) return 'Year level must be from 1 to 4.';
    return '';
  };

  const enrollmentPayload = () => ({
    curriculumId: form.curriculumId || undefined,
    schoolYear: form.schoolYear,
    semester: form.semester,
    yearLevel: form.yearLevel,
  });

  const upload = async (mode) => {
    const validationError = validateContext();
    if (validationError) return setResult({ status: 'Error', message: validationError });
    if (!file) return setResult({ status: 'Error', message: 'Choose a CSV or XLSX file first.' });
    if (file.size > 10 * 1024 * 1024) return setResult({ status: 'Error', message: 'Enrollment files cannot exceed 10 MB.' });

    setSaving(true); setResult(null);
    try {
      const response = mode === 'update'
        ? await registrarBulkUpdateStudents(file, form.department, enrollmentPayload())
        : await registrarBulkEnrollStudents(file, form.department, enrollmentPayload());
      setResult(response);
      await load();
    } catch (error) {
      setResult({ status: 'Error', message: error.message || 'Enrollment upload failed.' });
    } finally {
      setSaving(false);
    }
  };

  const enrollManualStudent = async (event) => {
    event.preventDefault();
    const validationError = validateContext();
    if (validationError) return setResult({ status: 'Error', message: validationError });
    setSaving(true); setResult(null);
    try {
      const csv = buildCsvContent([
        ['First Name', 'Last Name', 'Middle Name', 'Birthdate', 'Email Address', 'Contact Number', 'Home Address'],
        [manualForm.firstName, manualForm.lastName, manualForm.middleName, manualForm.birthdate, manualForm.email, manualForm.contactNumber, manualForm.homeAddress],
      ]);
      const manualFile = new File([csv], 'manual-student-enrollment.csv', { type: 'text/csv' });
      const response = await registrarBulkEnrollStudents(manualFile, form.department, enrollmentPayload());
      setResult(response);
      setManualForm({ firstName: '', lastName: '', middleName: '', birthdate: '', email: '', contactNumber: '', homeAddress: '' });
      await load();
    } catch (error) {
      setResult({ status: 'Error', message: error.message || 'Student enrollment failed.' });
    } finally {
      setSaving(false);
    }
  };

  const downloadTemplate = () => {
    downloadCsvFile(buildCsvContent([
      ['First Name', 'Last Name', 'Middle Name', 'Birthdate', 'Email Address', 'Contact Number', 'Home Address'],
      ['Juan', 'Dela Cruz', 'Andres', '05/15/2005', 'juan.delacruz@plv.edu.ph', '09123456789', 'Valenzuela City'],
    ]), `student-enrollment-${form.schoolYear}.csv`);
  };

  return (
    <div className="space-y-4">
      <div>
        <div><h3 className="text-xl font-bold text-[#003366]">Student Enrollment</h3></div>
      </div>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-bold text-[#003366]">Enrollment Setup</h3>

        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <label className="text-xs font-semibold text-slate-700">Academic Program
            <select value={form.department} onChange={(event) => updateField('department', event.target.value)} className="mt-1 h-10 w-full rounded-lg border border-slate-300 bg-white px-3 text-xs font-normal">
              {programs.map((program) => <option key={program} value={program}>{program}</option>)}
            </select>
          </label>
          <label className="text-xs font-semibold text-slate-700">School Year
            <input value={form.schoolYear} onChange={(event) => updateField('schoolYear', event.target.value)} placeholder="2026-2027" className="mt-1 h-10 w-full rounded-lg border border-slate-300 px-3 text-xs font-normal" />
          </label>
          <label className="text-xs font-semibold text-slate-700">Year Level
            <select value={form.yearLevel} onChange={(event) => updateField('yearLevel', event.target.value)} className="mt-1 h-10 w-full rounded-lg border border-slate-300 bg-white px-3 text-xs font-normal">
              {[1, 2, 3, 4].map((year) => <option key={year} value={year}>{year}{year === 1 ? 'st' : year === 2 ? 'nd' : year === 3 ? 'rd' : 'th'} Year</option>)}
            </select>
          </label>
          <label className="text-xs font-semibold text-slate-700">Semester
            <select value={form.semester} onChange={(event) => updateField('semester', event.target.value)} className="mt-1 h-10 w-full rounded-lg border border-slate-300 bg-white px-3 text-xs font-normal">
              <option value="FIRST">First Semester</option>
              <option value="SECOND">Second Semester</option>
              <option value="MIDYEAR">Midyear</option>
            </select>
          </label>
          <label className="text-xs font-semibold text-slate-700">Curriculum Version
            <select value={form.curriculumId} onChange={(event) => updateField('curriculumId', event.target.value)} className="mt-1 h-10 w-full rounded-lg border border-slate-300 bg-white px-3 text-xs font-normal">
              <option value="">Latest published version (automatic)</option>
              {matchingCurricula.map((curriculum) => <option key={curriculum.curriculumId} value={curriculum.curriculumId}>{curriculum.curriculumVersion} · {curriculum.curriculumName}</option>)}
            </select>
          </label>
        </div>

        {matchingCurricula.length === 0 ? <p className="mt-3 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">No published curriculum exists for this program yet. Enrollment can continue, but the Registrar must assign a published version later.</p> : null}
      </section>

      {result ? <section className={`rounded-xl border p-4 text-sm ${result.status === 'Error' || result.failed > 0 ? 'border-amber-300 bg-amber-50 text-amber-900' : 'border-emerald-200 bg-emerald-50 text-emerald-900'}`}><p className="font-bold">{result.status || 'Result'}</p><p>{result.message}</p>{typeof result.successful !== 'undefined' ? <p className="mt-1">Successful: {result.successful} · Failed: {result.failed || 0}</p> : null}{result.errors?.length ? <ul className="mt-2 max-h-40 list-disc overflow-y-auto pl-5">{result.errors.slice(0, 20).map((item, index) => <li key={`${item.row || index}-${item.identifier || ''}`}>Row {item.row || '?'} ({item.identifier || 'Unknown'}): {item.reason}</li>)}</ul> : null}</section> : null}

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h4 className="text-sm font-bold text-[#003366]">Enrollment Method</h4>
        <div className="mt-3 flex border-b border-slate-200">
          <button type="button" onClick={() => setEnrollmentMethod('bulk')} className={`border-b-2 px-5 py-2 text-xs font-bold transition ${enrollmentMethod === 'bulk' ? 'border-blue-700 bg-blue-50 text-blue-700' : 'border-transparent text-slate-500 hover:text-[#003366]'}`}>⇧ &nbsp; Bulk Upload</button>
          <button type="button" onClick={() => setEnrollmentMethod('manual')} className={`border-b-2 px-5 py-2 text-xs font-bold transition ${enrollmentMethod === 'manual' ? 'border-blue-700 bg-blue-50 text-blue-700' : 'border-transparent text-slate-500 hover:text-[#003366]'}`}>♙ &nbsp; Manual Entry</button>
        </div>

        {enrollmentMethod === 'bulk' ? <div>
          <label className="mt-4 flex min-h-24 cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-blue-300 bg-blue-50/30 p-4 text-center text-xs font-semibold text-blue-700">
            <span>Drag and drop your file here, or click to browse</span>
            <span className="mt-1 text-[10px] font-normal text-slate-500">Accepted file type: .xlsx or .csv</span>
            <input type="file" accept=".csv,.xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" onChange={(event) => setFile(event.target.files?.[0] || null)} className="sr-only" />
            {file ? <span className="mt-2 text-emerald-700">{file.name}</span> : null}
          </label>
          <div className="mt-4 flex flex-wrap gap-2">
            <button type="button" onClick={downloadTemplate} className={downloadTemplateButtonClass}>Download Template</button>
            <button type="button" disabled={saving} onClick={() => upload('enroll')} className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-bold text-white disabled:opacity-50">{saving ? 'Saving…' : 'Upload & Enroll'}</button>
          </div>
        </div> : <form onSubmit={enrollManualStudent} className="pt-4">
          <div className="mb-4 flex items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-50 text-lg text-blue-700">♙</span><div><h5 className="text-sm font-bold text-[#003366]">Manual Student Enrollment</h5></div></div>
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <h6 className="bg-slate-50 px-4 py-3 text-xs font-bold text-[#003366]">Student Information</h6>
            <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
              {[
                ['firstName', 'First Name', 'Enter first name', true, 'text'],
                ['lastName', 'Last Name', 'Enter last name', true, 'text'],
                ['middleName', 'Middle Name', 'Enter middle name (optional)', false, 'text'],
                ['birthdate', 'Birthdate', 'Select birthdate', true, 'date'],
                ['email', 'Email Address', 'e.g. student@plv.edu.ph', true, 'email'],
                ['contactNumber', 'Contact Number', 'Enter contact number', true, 'tel'],
              ].map(([field, label, placeholder, required, type]) => <label key={field} className="text-[10px] font-semibold text-slate-700">{label}{required && <span className="text-red-500"> *</span>}<input required={required} type={type} value={manualForm[field]} onChange={(event) => setManualForm((current) => ({ ...current, [field]: event.target.value }))} placeholder={placeholder} className="mt-1 h-9 w-full rounded-lg border border-slate-300 px-3 text-xs font-normal outline-none focus:border-blue-600" /></label>)}
              <label className="text-[10px] font-semibold text-slate-700 md:col-span-2 xl:col-span-3">Home Address <span className="text-red-500">*</span><textarea required value={manualForm.homeAddress} onChange={(event) => setManualForm((current) => ({ ...current, homeAddress: event.target.value }))} placeholder="Enter complete home address" rows="2" className="mt-1 w-full resize-none rounded-lg border border-slate-300 px-3 py-2 text-xs font-normal outline-none focus:border-blue-600" /></label>
            </div>
            
            <div className="mt-4 flex justify-end gap-2 border-t border-slate-100 p-4"><button type="button" onClick={() => setManualForm({ firstName: '', lastName: '', middleName: '', birthdate: '', email: '', contactNumber: '', homeAddress: '' })} className="rounded-lg border border-slate-300 px-4 py-2 text-xs font-bold text-slate-600">Cancel</button><button disabled={saving || loading} className="rounded-lg bg-[#003366] px-4 py-2 text-xs font-bold text-white disabled:opacity-50">{saving ? 'Saving…' : '♙  Save Student'}</button></div>
          </div>
        </form>}
      </section>

      <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="flex flex-col gap-3 border-b border-slate-200 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"><h4 className="text-sm font-bold text-[#003366]">Current Student Enrollments</h4><div className="flex gap-2"><input value={enrollmentSearch} onChange={(event) => setEnrollmentSearch(event.target.value)} placeholder="Search by student name or ID..." className="h-9 w-full rounded-lg border border-slate-300 px-3 text-xs outline-none sm:w-64"/><button type="button" onClick={load} className="rounded-lg border border-blue-200 px-3 py-2 text-xs font-semibold text-blue-700">Refresh</button></div></div>
        <div className="overflow-x-auto"><table className="min-w-full text-left text-xs"><thead><tr className="bg-slate-50 text-slate-600"><th className="px-4 py-3">Student</th><th className="px-4 py-3">Program / Year Level</th><th className="px-4 py-3">School Year</th><th className="px-4 py-3">Curriculum</th><th className="px-4 py-3">Status</th></tr></thead><tbody>{visibleStudents.map((student) => <tr key={student.id} className="border-b"><td className="px-4 py-3"><span className="block font-semibold">{student.fullname}</span><span className="text-xs text-slate-500">{student.studentno}</span></td><td className="px-4 py-3">{student.department || 'Unassigned'}<span className="block text-xs text-slate-500">Year {student.yearLevel || '—'}</span></td><td className="px-4 py-3">{student.schoolYear || '—'}</td><td className="px-4 py-3">{student.curriculumVersion || 'Not assigned'}</td><td className="px-4 py-3">{student.enrollmentStatus || student.assignmentStatus || 'Unassigned'}</td></tr>)}{!loading && visibleStudents.length === 0 ? <tr><td colSpan="5" className="px-4 py-8 text-center text-slate-500">No active student enrollment yet.</td></tr> : null}</tbody></table></div>
      </section>
    </div>
  );
};

export default StudentEnrollmentManagement;
