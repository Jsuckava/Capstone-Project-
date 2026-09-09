import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { fetchStudentCurriculum, fetchStudentHistoricalGrades, getSystemSetting } from '../../services/api';
import StudentNavbar from './StudentNavbar';
import StudentInfoCard from './StudentInfoCard';
import StudentSummary from './StudentSummary';
import StudentHistoricalGrades from './StudentHistoricalGrades';
import StudentBlockchainTransactions from './StudentBlockchainTransactions';
import CurriculumViewer from '../shared/CurriculumViewer';
import { getGradeEquivalent } from '../../utils/gradingHelpers';

const StudentPortal = ({ studentData, onLogout }) => {
  const [grades, setGrades] = useState([]);
  const [gradeError, setGradeError] = useState('');
  const [gradeMessage, setGradeMessage] = useState('');
  const [curricula, setCurricula] = useState([]);
  const [loading, setLoading] = useState(true);
  const [curriculumLoading, setCurriculumLoading] = useState(false);
  const [curriculumError, setCurriculumError] = useState('');
  const [activeSemester, setActiveSemester] = useState('Semester Grades');
  const [activeView, setActiveView] = useState('grades');

  const rawFullName = studentData.name || '';
  const firstName = rawFullName.split(' ')[0] || '';
  const storedMiddleName = studentData.middleName || '';
  const remainingName = rawFullName.split(' ').slice(1).join(' ').trim();
  const escapedMiddleName = storedMiddleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const lastName = storedMiddleName && escapedMiddleName ? remainingName.replace(new RegExp(`^${escapedMiddleName}\\s*`, 'i'), '').trim() : remainingName;

  const loadGrades = useCallback(async (background = false) => {
    if (!background) setLoading(true);
    setGradeError('');
    try {
      const response = await fetchStudentHistoricalGrades();
      const records = Array.isArray(response?.data) ? response.data : [];
      setGrades(records);
      setGradeMessage(records.length === 0
        ? (response?.message || 'There are currently no grade records available.')
        : '');
    } catch (error) {
      console.error('Unable to load finalized student grade history:', error);
      setGradeError(error.message || 'Unable to retrieve grade records from the blockchain. Please try again later.');
      setGradeMessage('');
      if (!background) setGrades([]);
    } finally { if (!background) setLoading(false); }
  }, []);

  const loadCurriculum = useCallback(async () => {
    setCurriculumLoading(true); setCurriculumError('');
    try {
      const response = await fetchStudentCurriculum();
      setCurricula(response?.data ? [response.data] : []);
    } catch (error) {
      setCurricula([]); setCurriculumError(error.message || 'No published curriculum is assigned to your account.');
    } finally { setCurriculumLoading(false); }
  }, []);

  useEffect(() => {
    loadGrades();
    const handleAcademicDataChanged = () => loadGrades(true);
    window.addEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
    return () => window.removeEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
  }, [loadGrades]);

  useEffect(() => { if (activeView === 'curriculum' && curricula.length === 0) loadCurriculum(); }, [activeView, curricula.length, loadCurriculum]);

  useEffect(() => {
    const applyEncodingPeriod = (value) => {
      if (!value) return;
      try { const parsed = typeof value === 'string' ? JSON.parse(value) : value; setActiveSemester(parsed?.semester ? `${parsed.semester} Grades` : 'Semester Grades'); }
      catch (error) { console.error('Failed to parse encoding period:', error); }
    };
    getSystemSetting('encoding_period').then((response) => { if (response.status === 'Success') applyEncodingPeriod(response.value); }).catch(() => {});
    const handleSetting = (event) => { if ((event.detail?.key || event.detail?.Key) === 'encoding_period') applyEncodingPeriod(event.detail?.value || event.detail?.Value); };
    window.addEventListener('blockgo:system-setting-changed', handleSetting);
    return () => window.removeEventListener('blockgo:system-setting-changed', handleSetting);
  }, []);

  const finalizedByRecord = useMemo(() => {
    const map = new Map();
    grades.forEach((grade) => {
      const existing = map.get(grade.recordId) || grade;
      if (grade.term === 'finals' || !map.has(grade.recordId)) map.set(grade.recordId, { ...existing, ...grade });
    });
    return [...map.values()];
  }, [grades]);
  const equivalentFor = (grade) => {
    const numericGrade = Number(grade.finalAverage || grade.grade);
    if (!Number.isFinite(numericGrade)) return null;
    return numericGrade > 5 ? Number(getGradeEquivalent(numericGrade)) : numericGrade;
  };
  const totalUnits = finalizedByRecord.reduce((sum, grade) => sum + Number(grade.units || 0), 0);
  const totalWeight = finalizedByRecord.reduce((sum, grade) => sum + Number(equivalentFor(grade) || 0) * Number(grade.units || 0), 0);
  const calculatedGWA = totalUnits > 0 ? (totalWeight / totalUnits).toFixed(2) : '0.00';
  const failedSubjectsCount = finalizedByRecord.filter((grade) => equivalentFor(grade) === 5).length;
  const isDeansLister = finalizedByRecord.length > 0 && Number(calculatedGWA) <= 1.75 && finalizedByRecord.every((grade) => {
    const equivalent = equivalentFor(grade);
    return equivalent !== null && equivalent <= 2.25;
  });
  const currentYear = Number(String(studentData.yearLevel || studentData.section || '').match(/[1-4]/)?.[0] || 0);

  const views = [
    { id: 'grades', label: 'My Grades' },
    { id: 'curriculum', label: 'Curriculum Checklist' },
    { id: 'transactions', label: 'Blockchain Transactions' },
  ];

  return (
    <div className="min-h-screen bg-slate-50 pb-10 font-sans">
      <StudentNavbar onLogout={onLogout} />
      <div className="mx-auto max-w-7xl">
        <StudentInfoCard studentData={{ firstName, lastName, middleName: storedMiddleName || 'Not provided', studentId: studentData.studentNo || 'N/A', dateOfBirth: studentData.dateOfBirth || 'Not provided', sex: studentData.sex || 'Not provided', phone: studentData.phone || 'Not provided', email: studentData.studentEmail || studentData.email, department: studentData.department, section: studentData.section, yearLevel: studentData.yearLevel, schoolYear: studentData.schoolYear, semester: studentData.semester, enrollmentStatus: studentData.enrollmentStatus, curriculumName: studentData.curriculumName, curriculumVersion: studentData.curriculumVersion, address: studentData.address || 'Not provided' }} />
        <StudentSummary totalUnits={totalUnits} gwa={calculatedGWA} isDeansLister={isDeansLister} failedSubjectsCount={failedSubjectsCount} semesterLabel={activeSemester} />

        <div className="mx-6 mt-6 flex flex-wrap gap-2">{views.map((view) => <button key={view.id} type="button" onClick={() => setActiveView(view.id)} className={`rounded-lg px-4 py-2 text-sm font-bold ${activeView === view.id ? 'bg-[#003366] text-white' : 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'}`}>{view.label}</button>)}</div>
        <main className="mx-6 mt-4">
          {activeView === 'grades' ? <StudentHistoricalGrades grades={grades} loading={loading} error={gradeError} emptyMessage={gradeMessage} /> : null}
          {activeView === 'transactions' ? <StudentBlockchainTransactions /> : null}
          {activeView === 'curriculum' ? <>{curriculumError ? <div className="mb-3 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">{curriculumError}</div> : null}<CurriculumViewer curricula={curricula} currentYear={currentYear} loading={curriculumLoading} emptyMessage={curriculumError || 'No published curriculum is assigned to your account.'} /></> : null}
        </main>
      </div>
    </div>
  );
};

export default StudentPortal;
