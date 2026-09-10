import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { fetchStudentCurriculum, fetchStudentHistoricalGrades, getSystemSetting, updateStudentProfile } from '../../services/api';
import StudentNavbar from './StudentNavbar';
import StudentInfoCard from './StudentInfoCard';
import StudentSummary from './StudentSummary';
import StudentHistoricalGrades from './StudentHistoricalGrades';
import StudentBlockchainTransactions from './StudentBlockchainTransactions';
import StudentCurrentSubjects from './StudentCurrentSubjects';
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
  const [showTransactions, setShowTransactions] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [profile, setProfile] = useState(() => ({ ...studentData }));
  const [profileForm, setProfileForm] = useState(() => ({ phone: studentData.phone || '', sex: studentData.sex || '', middleName: studentData.middleName || '' }));
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileNotice, setProfileNotice] = useState('');

  const rawFullName = profile.name || '';
  const firstName = rawFullName.split(' ')[0] || '';
  const storedMiddleName = profile.middleName || '';
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
  const currentYear = Number(String(profile.yearLevel || profile.section || '').match(/[1-4]/)?.[0] || 0);

  const views = [
    { id: 'grades', label: 'Current Subjects' },
    { id: 'history', label: 'Grade History' },
    { id: 'curriculum', label: 'Curriculum Checklist' },
  ];

  const saveProfile = async (event) => {
    event.preventDefault(); setProfileSaving(true); setProfileNotice('');
    try {
      await updateStudentProfile(profileForm);
      setProfile((current) => ({ ...current, ...profileForm }));
      setProfileNotice('Profile settings saved.');
    } catch (error) { setProfileNotice(error.message || 'Profile settings could not be saved.'); }
    finally { setProfileSaving(false); }
  };

  return (
    <div className="min-h-screen bg-slate-50 pb-10 font-sans">
      <StudentNavbar onLogout={onLogout} onOpenSettings={() => setShowSettings(true)} />
      <div className="mx-auto max-w-7xl">
        <StudentInfoCard studentData={{ firstName, lastName, middleName: storedMiddleName || 'Not provided', studentId: profile.studentNo || 'N/A', dateOfBirth: profile.dateOfBirth || 'Not provided', sex: profile.sex || 'Not provided', phone: profile.phone || 'Not provided', email: profile.studentEmail || profile.email, department: profile.department, section: profile.section, yearLevel: profile.yearLevel, schoolYear: profile.schoolYear, semester: profile.semester, enrollmentStatus: profile.enrollmentStatus, curriculumName: profile.curriculumName, curriculumVersion: profile.curriculumVersion, address: profile.address || 'Not provided' }} />
        <StudentSummary totalUnits={totalUnits} gwa={calculatedGWA} isDeansLister={isDeansLister} failedSubjectsCount={failedSubjectsCount} semesterLabel={activeSemester} />

        <div className="mx-6 mt-6 flex flex-wrap gap-2">{views.map((view) => <button key={view.id} type="button" onClick={() => { setActiveView(view.id); setShowTransactions(false); }} className={`rounded-lg px-4 py-2 text-sm font-bold ${activeView === view.id && !showTransactions ? 'bg-[#003366] text-white' : 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'}`}>{view.label}</button>)}<button type="button" onClick={() => setShowTransactions((value) => !value)} className={`rounded-lg px-4 py-2 text-sm font-bold ${showTransactions ? 'bg-[#003366] text-white' : 'border border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100'}`}>{showTransactions ? 'Hide my blockchain transactions' : 'View my blockchain transactions'}</button></div>
        <main className="mx-6 mt-4">
          {showTransactions ? <StudentBlockchainTransactions /> : null}
          {!showTransactions && activeView === 'grades' ? <StudentCurrentSubjects grades={grades} schoolYear={profile.schoolYear} semester={profile.semester} loading={loading} error={gradeError} /> : null}
          {!showTransactions && activeView === 'history' ? <StudentHistoricalGrades grades={grades} loading={loading} error={gradeError} emptyMessage={gradeMessage} /> : null}
          {!showTransactions && activeView === 'curriculum' ? <>{curriculumError ? <div className="mb-3 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">{curriculumError}</div> : null}<CurriculumViewer curricula={curricula} currentYear={currentYear} loading={curriculumLoading} emptyMessage={curriculumError || 'No published curriculum is assigned to your account.'} /></> : null}
        </main>
      </div>
      {showSettings ? <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4" role="dialog" aria-modal="true" aria-label="Profile settings"><form onSubmit={saveProfile} className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl"><div className="flex items-center justify-between"><div><p className="text-xs font-bold uppercase text-slate-500">Student Profile</p><h2 className="text-xl font-bold text-[#003366]">Profile Settings</h2></div><button type="button" onClick={() => setShowSettings(false)} aria-label="Close profile settings" className="text-2xl text-slate-500">×</button></div>{profileNotice ? <p className="mt-4 rounded-lg bg-blue-50 p-3 text-sm text-blue-800">{profileNotice}</p> : null}<div className="mt-5 grid gap-4 sm:grid-cols-2"><label className="text-xs font-semibold text-slate-700">Middle Name<input value={profileForm.middleName} onChange={(event) => setProfileForm((current) => ({ ...current, middleName: event.target.value }))} className="mt-1 h-10 w-full rounded-lg border border-slate-300 px-3 text-sm" /></label><label className="text-xs font-semibold text-slate-700">Phone<input value={profileForm.phone} onChange={(event) => setProfileForm((current) => ({ ...current, phone: event.target.value }))} className="mt-1 h-10 w-full rounded-lg border border-slate-300 px-3 text-sm" /></label><label className="text-xs font-semibold text-slate-700 sm:col-span-2">Sex<select value={profileForm.sex} onChange={(event) => setProfileForm((current) => ({ ...current, sex: event.target.value }))} className="mt-1 h-10 w-full rounded-lg border border-slate-300 bg-white px-3 text-sm"><option value="">Prefer not to specify</option><option value="Female">Female</option><option value="Male">Male</option></select></label></div><div className="mt-6 flex justify-end gap-2"><button type="button" onClick={() => setShowSettings(false)} className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold">Cancel</button><button disabled={profileSaving} className="rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white disabled:opacity-50">{profileSaving ? 'Saving…' : 'Save Settings'}</button></div></form></div> : null}
    </div>
  );
};

export default StudentPortal;
