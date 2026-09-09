import React, { useCallback, useEffect, useState } from 'react';
import { approveCurriculum, archiveCurriculum, assignStudentCurriculum, fetchCurriculums, publishCurriculum, returnCurriculum } from '../../services/api';
import CurriculumViewer from '../shared/CurriculumViewer';

const tabs = ['ALL', 'PENDING_APPROVAL', 'APPROVED', 'PUBLISHED', 'ARCHIVED'];
const labels = { ALL: 'All Curricula', PENDING_APPROVAL: 'Pending Approval', APPROVED: 'Approved', PUBLISHED: 'Published', ARCHIVED: 'Archived' };

const CurriculumManagement = () => {
  const [curricula, setCurricula] = useState([]);
  const [activeTab, setActiveTab] = useState('PENDING_APPROVAL');
  const [selectedId, setSelectedId] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState(null);
  const [studentEmail, setStudentEmail] = useState('');
  const load = useCallback(async () => { setLoading(true); try { const response = await fetchCurriculums(); const items = Array.isArray(response?.data) ? response.data : []; setCurricula(items); setSelectedId((current) => current || String(items[0]?.curriculumId || '')); } catch (error) { setNotice({ type: 'error', message: error.message }); } finally { setLoading(false); } }, []);
  useEffect(() => { load(); }, [load]);
  const filtered = activeTab === 'ALL' ? curricula : curricula.filter((curriculum) => curriculum.status === activeTab);
  const selected = curricula.find((curriculum) => String(curriculum.curriculumId) === String(selectedId));
  useEffect(() => { if (filtered.length && !filtered.some((item) => String(item.curriculumId) === String(selectedId))) setSelectedId(String(filtered[0].curriculumId)); }, [filtered, selectedId]);

  const action = async (name) => {
    if (!selected) return;
    setSaving(true); setNotice(null);
    try {
      if (name === 'approve') { if (!window.confirm('Approve this curriculum proposal?')) return; await approveCurriculum(selected.curriculumId); }
      if (name === 'return') { const reason = window.prompt('Reason for returning this curriculum:'); if (!reason?.trim()) return; await returnCurriculum(selected.curriculumId, reason.trim()); }
      if (name === 'publish') { if (!window.confirm('Publish this approved curriculum? Any previous published version for this program will be archived.')) return; await publishCurriculum(selected.curriculumId); }
      if (name === 'archive') { if (!window.confirm('Archive this published curriculum? It will remain in version history.')) return; await archiveCurriculum(selected.curriculumId); }
      setNotice({ type: 'success', message: `Curriculum ${name} action completed.` }); await load();
    } catch (error) { setNotice({ type: 'error', message: error.message }); }
    finally { setSaving(false); }
  };
  const assign = async (event) => { event.preventDefault(); if (!selected || !studentEmail) return; setSaving(true); try { await assignStudentCurriculum(selected.curriculumId, studentEmail); setNotice({ type: 'success', message: 'Curriculum assigned to student.' }); setStudentEmail(''); } catch (error) { setNotice({ type: 'error', message: error.message }); } finally { setSaving(false); } };

  return <div className="space-y-5">{notice ? <div className={`rounded-lg p-3 text-sm ${notice.type === 'error' ? 'bg-red-50 text-red-700' : 'bg-emerald-50 text-emerald-800'}`}>{notice.message}</div> : null}<div className="flex flex-wrap gap-2">{tabs.map((tab) => <button key={tab} onClick={() => setActiveTab(tab)} className={`rounded-lg px-4 py-2 text-sm font-bold ${activeTab === tab ? 'bg-[#003366] text-white' : 'border border-slate-300 bg-white text-slate-700'}`}>{labels[tab]} ({tab === 'ALL' ? curricula.length : curricula.filter((item) => item.status === tab).length})</button>)}</div><div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]"><aside className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"><h2 className="mb-3 font-bold text-[#003366]">Curriculum Versions</h2>{loading ? <p className="py-6 text-center text-slate-500">Loading…</p> : <div className="space-y-2">{filtered.map((curriculum) => <button key={curriculum.curriculumId} onClick={() => setSelectedId(String(curriculum.curriculumId))} className={`w-full rounded-lg border p-3 text-left ${String(curriculum.curriculumId) === String(selectedId) ? 'border-[#003366] bg-blue-50' : 'border-slate-200 hover:bg-slate-50'}`}><span className="block font-bold text-slate-800">{curriculum.programCode} · {curriculum.curriculumVersion}</span><span className="text-xs text-slate-500">{curriculum.status} · {curriculum.subjects?.length || 0} subjects · {curriculum.totalUnits || 0} units</span><span className="mt-1 block text-xs text-slate-500">Created by {curriculum.createdByName}</span></button>)}{filtered.length === 0 ? <p className="py-6 text-center text-slate-400">No curricula in this status.</p> : null}</div>}</aside><main className="min-w-0">{selected ? <><div className="mb-3 flex flex-wrap gap-2">{selected.status === 'PENDING_APPROVAL' ? <><button disabled={saving} onClick={() => action('approve')} className="rounded-lg bg-emerald-700 px-4 py-2 font-bold text-white">Approve</button><button disabled={saving} onClick={() => action('return')} className="rounded-lg bg-amber-500 px-4 py-2 font-bold text-white">Return for Revision</button></> : null}{selected.status === 'APPROVED' ? <button disabled={saving} onClick={() => action('publish')} className="rounded-lg bg-blue-700 px-4 py-2 font-bold text-white">Publish</button> : null}{selected.status === 'PUBLISHED' ? <><button disabled={saving} onClick={() => action('archive')} className="rounded-lg bg-slate-700 px-4 py-2 font-bold text-white">Archive</button><form onSubmit={assign} className="flex gap-2"><input required type="email" placeholder="Student email for assignment" value={studentEmail} onChange={(e) => setStudentEmail(e.target.value)} className="rounded-lg border border-slate-300 px-3 py-2" /><button className="rounded-lg bg-[#003366] px-3 py-2 text-sm font-bold text-white">Assign</button></form></> : null}</div>{selected.registrarComment ? <div className="mb-3 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">Registrar comment: {selected.registrarComment}</div> : null}<CurriculumViewer curricula={[selected]} /></> : <div className="rounded-xl border border-dashed border-slate-300 bg-white p-10 text-center text-slate-500">Select a curriculum to review.</div>}</main></div></div>;
};

export default CurriculumManagement;
