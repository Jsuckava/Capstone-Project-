import React, { useCallback, useEffect, useState } from 'react';
import { fetchPasswordResetRequests } from '../../services/api';

const PasswordResetRequests = () => {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { const response = await fetchPasswordResetRequests(); setRequests(Array.isArray(response?.data) ? response.data : []); }
    catch (requestError) { setError(requestError.message || 'Unable to load password reset requests.'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  return <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm sm:p-4">
    <div className="mb-3 flex items-start justify-between gap-3">
      <div className="flex items-start gap-2">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-blue-50 text-blue-600"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4"><path d="M7 6h13M7 12h13M7 18h13"/><circle cx="3" cy="6" r="1" fill="currentColor"/><circle cx="3" cy="12" r="1" fill="currentColor"/><circle cx="3" cy="18" r="1" fill="currentColor"/></svg></span>
        <div><h2 className="text-sm font-bold text-slate-800">Password Reset Requests</h2></div>
      </div>
      <button type="button" onClick={load} disabled={loading} className="inline-flex items-center gap-1.5 rounded-md border border-blue-200 px-3 py-1.5 text-[10px] font-semibold text-blue-700 hover:bg-blue-50 disabled:opacity-50"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-3.5 w-3.5"><path d="M20 6v5h-5M4 18v-5h5"/><path d="M6 9a7 7 0 0 1 12-2l2 2M4 15l2 2a7 7 0 0 0 12-2"/></svg>Refresh</button>
    </div>
    {error && <div className="mb-3 rounded-md border border-red-200 bg-red-50 p-2 text-xs text-red-700">{error}</div>}
    {loading ? <div className="rounded-md border border-slate-200 bg-slate-50 p-6 text-center text-xs text-slate-500">Loading reset requests…</div> : requests.length === 0 ? <div className="rounded-md border border-slate-200 bg-slate-50/60 p-6 text-center"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mx-auto h-8 w-8 text-slate-300"><path d="M5 8h14l1 12H4L5 8Z"/><path d="M8 8a4 4 0 0 1 8 0"/></svg><p className="mt-2 text-[11px] font-semibold text-slate-600">No password reset requests in the last 24 hours.</p></div> : <div className="space-y-2">{requests.map((request) => <article key={request.requestId} className="rounded-md border border-slate-200 p-3"><div className="flex flex-wrap items-start justify-between gap-2"><div><h3 className="text-xs font-bold text-slate-800">{request.email}</h3><p className="mt-0.5 text-[10px] text-slate-500">Requested {new Date(request.createdAt).toLocaleString()}</p></div><span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${request.status === 'ACTIVE' ? 'bg-emerald-100 text-emerald-800' : request.status === 'USED' ? 'bg-slate-100 text-slate-700' : 'bg-amber-100 text-amber-800'}`}>{request.status}</span></div><div className="mt-2 flex flex-wrap items-center gap-2"><span className="rounded-md bg-blue-50 px-3 py-1.5 font-mono text-sm font-bold tracking-[0.25em] text-[#003366]">{request.otp}</span><span className="text-[10px] text-slate-500">Expires {new Date(request.expiresAt).toLocaleString()}</span></div></article>)}</div>}
  </section>;
};

export default PasswordResetRequests;
