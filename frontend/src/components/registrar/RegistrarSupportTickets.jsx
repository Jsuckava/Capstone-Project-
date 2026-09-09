import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createSupportTicket, fetchSupportSpecialists, fetchSupportTickets } from '../../services/api';
import SupportAssignmentSelect, { assignmentPayload } from '../shared/SupportAssignmentSelect';

const initialForm = { title: '', description: '', severity: 'NORMAL', assignment: '' };
const severityStyles = { LOW: 'bg-emerald-500', NORMAL: 'bg-blue-500', HIGH: 'bg-red-500' };

const Icon = ({ children, className = 'h-4 w-4' }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>
);

const RegistrarSupportTickets = () => {
  const [tickets, setTickets] = useState([]);
  const [specialists, setSpecialists] = useState([]);
  const [form, setForm] = useState(initialForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState(null);
  const [files, setFiles] = useState([]);
  const fileInputRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ticketResponse, specialistResponse] = await Promise.all([fetchSupportTickets(), fetchSupportSpecialists()]);
      setTickets(Array.isArray(ticketResponse?.data) ? ticketResponse.data : []);
      setSpecialists(Array.isArray(specialistResponse?.data) ? specialistResponse.data : []);
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const submit = async (event) => {
    event.preventDefault();
    const assignment = assignmentPayload(form.assignment);
    if (!assignment) {
      setNotice({ type: 'error', message: 'Select the support specialist who should receive this ticket.' });
      return;
    }
    setSaving(true);
    setNotice(null);
    try {
      await createSupportTicket({
        title: form.title,
        description: form.description,
        severity: form.severity,
        ...assignment,
      });
      setForm(initialForm);
      setFiles([]);
      if (fileInputRef.current) fileInputRef.current.value = '';
      setNotice({ type: 'success', message: 'Error report sent to the System Administrator.' });
      await load();
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3 text-slate-800">
      {notice && <div className={`rounded-lg border p-3 text-sm ${notice.type === 'error' ? 'border-red-200 bg-red-50 text-red-700' : 'border-emerald-200 bg-emerald-50 text-emerald-800'}`}>{notice.message}</div>}

      <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm sm:p-4">
        <div className="mb-4 flex items-center justify-between rounded-md border border-blue-100 bg-blue-50 px-3 py-2 text-blue-950">
          <div className="flex items-start gap-3">
            <Icon className="mt-0.5 h-4 w-4 shrink-0 text-blue-600"><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></Icon>
            <div><p className="text-xs font-bold">Keep your information secure</p><p className="text-[11px] text-slate-600">Do not include passwords, tokens, or private keys in your ticket.</p></div>
          </div>
          <span className="ml-3 rounded-full bg-blue-100 p-1.5 text-blue-500"><Icon className="h-3.5 w-3.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /><path d="m9 12 2 2 4-4" /></Icon></span>
        </div>

        <form onSubmit={submit} className="space-y-3">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="block text-xs font-semibold text-slate-700">Issue Title <span className="text-red-500">*</span>
              <input required minLength="3" maxLength="200" placeholder="Short, descriptive title for the issue" value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} className="mt-1.5 w-full rounded-md border border-slate-300 px-3 py-2 text-xs font-normal outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-100" />
            </label>
            <div>
              <label className="block text-xs font-semibold text-slate-700">Priority <span className="text-red-500">*</span>
                <select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })} className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-xs font-normal outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-100">
                  <option value="LOW">Low</option><option value="NORMAL">Normal</option><option value="HIGH">High</option>
                </select>
              </label>
              
              <div className="mt-1 flex flex-wrap gap-1.5">{['LOW', 'NORMAL', 'HIGH'].map((level) => <span key={level} className="inline-flex items-center gap-1 rounded-full bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-600"><span className={`h-1.5 w-1.5 rounded-full ${severityStyles[level]}`} />{level.charAt(0) + level.slice(1).toLowerCase()}</span>)}</div>
            </div>
          </div>

          <label className="block text-xs font-semibold text-slate-700">Description <span className="text-red-500">*</span>
            <textarea required minLength="10" maxLength="5000" rows="4" placeholder="Describe the error and the steps that caused it. Include any relevant details." value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} className="mt-1.5 w-full resize-y rounded-md border border-slate-300 px-3 py-2 text-xs font-normal outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-100" />
          </label>

          <label className="block text-xs font-semibold text-slate-700">Support Specialist <span className="text-red-500">*</span>
            <SupportAssignmentSelect value={form.assignment} onChange={(assignment) => setForm({ ...form, assignment })} specialists={specialists} className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-xs font-normal outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-100" ariaLabel="Support specialist" />
          </label>

          <div className="flex flex-col gap-2 rounded-md border border-slate-200 bg-slate-50/60 px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-start gap-3">
              <Icon className="mt-0.5 h-4 w-4 shrink-0 text-slate-500"><path d="m21.4 11.6-8.9 8.9a6 6 0 0 1-8.5-8.5l9.6-9.6a4 4 0 0 1 5.7 5.7l-9.6 9.6a2 2 0 0 1-2.8-2.8l8.9-8.9" /></Icon>
              <div className="min-w-0"><p className="text-xs font-bold">Attach files <span className="font-normal text-slate-500">(optional)</span></p><p className="truncate text-[10px] text-slate-500">{files.length ? files.map((file) => file.name).join(', ') : 'Upload screenshots, logs, or documents to help us resolve the issue faster.'}</p></div>
            </div>
            <input ref={fileInputRef} type="file" multiple accept="image/*,.pdf,.txt,.log,.doc,.docx" onChange={(event) => setFiles(Array.from(event.target.files || []))} className="hidden" />
            <button type="button" onClick={() => fileInputRef.current?.click()} className="shrink-0 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50">Choose Files</button>
          </div>

          <div className="border-t border-slate-200 pt-3"><button disabled={saving} className="inline-flex items-center gap-1.5 rounded-md bg-[#073b7a] px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-[#052e61] disabled:cursor-not-allowed disabled:opacity-50"><Icon className="h-3.5 w-3.5"><path d="m22 2-7 20-4-9-9-4Z" /><path d="M22 2 11 13" /></Icon>{saving ? 'Submitting…' : 'Submit Ticket'}</button></div>
        </form>
      </section>

      <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm sm:p-4">
        <div className="mb-3 flex items-start justify-between gap-4">
          <div className="flex gap-2"><Icon className="mt-0.5 h-4 w-4 text-[#073b7a]"><path d="M4 4h16v5a3 3 0 0 0 0 6v5H4v-5a3 3 0 0 0 0-6Z" /><path d="M13 7v2M13 12v1M13 16v1" /></Icon><div><h2 className="text-base font-bold text-slate-800">My Tickets</h2></div></div>
          <button type="button" onClick={load} disabled={loading} className="inline-flex items-center gap-1.5 rounded-md border border-blue-200 bg-white px-2.5 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-50 disabled:opacity-50"><Icon className="h-3.5 w-3.5"><path d="M20 6v5h-5M4 18v-5h5" /><path d="M6.1 9a7 7 0 0 1 11.4-2.6L20 9M4 15l2.5 2.6A7 7 0 0 0 17.9 15" /></Icon>Refresh</button>
        </div>

        {loading ? <p className="rounded-lg border border-slate-200 bg-slate-50 py-12 text-center text-sm text-slate-500">Loading tickets…</p> : <div className="space-y-3">
          {tickets.map((ticket) => <article key={ticket.ticketId} className="rounded-lg border border-slate-200 p-4"><div className="flex flex-wrap justify-between gap-2"><h3 className="font-bold text-slate-800">#{ticket.ticketId} · {ticket.title}</h3><span className="rounded-full bg-blue-100 px-2.5 py-1 text-xs font-bold text-blue-800">{ticket.status}</span></div><p className="mt-2 whitespace-pre-wrap text-sm text-slate-600">{ticket.description}</p><p className="mt-2 text-xs text-slate-500">{ticket.severity} · {new Date(ticket.createdAt).toLocaleString()}</p>{ticket.assignedSpecialistLabel && <p className="mt-2 text-xs font-semibold text-indigo-700">Assigned to: {ticket.assignedSpecialistLabel}</p>}{ticket.adminResponse && <div className="mt-3 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800"><strong>System Administrator:</strong> {ticket.adminResponse}</div>}</article>)}
          {tickets.length === 0 && <div className="flex min-h-20 items-center justify-center rounded-md border border-slate-200 bg-slate-50/70 px-5 py-5 text-center"><div><Icon className="mx-auto h-7 w-7 text-blue-200"><path d="M4 7h5l2 2h9v10H4Z" /><path d="m14 6 4-2-1 4" /></Icon><p className="mt-1.5 text-xs font-bold text-slate-700">No support tickets submitted yet.</p></div></div>}
        </div>}
      </section>
    </div>
  );
};

export default RegistrarSupportTickets;
