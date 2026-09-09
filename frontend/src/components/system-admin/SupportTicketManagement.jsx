import React, { useCallback, useEffect, useState } from 'react';
import {
  broadcastSupportNotice,
  fetchSupportSpecialists,
  fetchSupportTickets,
  updateSupportTicket,
} from '../../services/api';
import SupportAssignmentSelect, { assignmentPayload, assignmentValueForTicket } from '../shared/SupportAssignmentSelect';

const SupportTicketManagement = () => {
  const [tickets, setTickets] = useState([]);
  const [specialists, setSpecialists] = useState([]);
  const [edits, setEdits] = useState({});
  const [broadcastMessage, setBroadcastMessage] = useState('');
  const [notice, setNotice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [savingTicketId, setSavingTicketId] = useState(null);
  const [broadcasting, setBroadcasting] = useState(false);

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

  const editFor = (ticket) => edits[ticket.ticketId] || {
    status: ticket.status,
    adminResponse: ticket.adminResponse || '',
    assignment: assignmentValueForTicket(ticket),
  };

  const changeEdit = (ticket, field, value) => setEdits((current) => ({
    ...current,
    [ticket.ticketId]: { ...editFor(ticket), [field]: value },
  }));

  const save = async (ticket) => {
    const edit = editFor(ticket);
    const assignment = assignmentPayload(edit.assignment);
    if (!assignment) {
      setNotice({ type: 'error', message: `Select one of the four support specialists for ticket #${ticket.ticketId}.` });
      return;
    }
    setSavingTicketId(ticket.ticketId);
    try {
      await updateSupportTicket(ticket.ticketId, { status: edit.status, adminResponse: edit.adminResponse, ...assignment });
      setNotice({ type: 'success', message: `Ticket #${ticket.ticketId} was saved.` });
      setEdits((current) => { const next = { ...current }; delete next[ticket.ticketId]; return next; });
      await load();
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setSavingTicketId(null);
    }
  };

  const broadcast = async (event) => {
    event.preventDefault();
    setBroadcasting(true);
    try {
      const response = await broadcastSupportNotice(broadcastMessage);
      setBroadcastMessage('');
      setNotice({ type: 'success', message: response?.data?.displayMessage || 'Notice broadcast to all logged-in users.' });
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setBroadcasting(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="text-xl font-bold text-[#003366]">Registrar Error Reports</h2></div>
        <button type="button" onClick={load} disabled={loading} className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-700 disabled:opacity-50">{loading ? 'Refreshing...' : 'Refresh'}</button>
      </div>

      {notice ? <div className={`rounded-lg p-3 text-sm ${notice.type === 'error' ? 'bg-red-50 text-red-700' : 'bg-emerald-50 text-emerald-800'}`}>{notice.message}</div> : null}

      <section className="rounded-xl border border-blue-200 bg-blue-50 p-5 shadow-sm">
        <h3 className="text-lg font-bold text-[#003366]">Broadcast Resolution Notice</h3>
        
        <form onSubmit={broadcast} className="mt-4 flex flex-col gap-3 lg:flex-row">
          <textarea required minLength="3" maxLength="1000" rows="3" value={broadcastMessage} onChange={(event) => setBroadcastMessage(event.target.value)} placeholder="Type the message users should receive." className="min-w-0 flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2" />
          <button disabled={broadcasting} className="self-stretch rounded-lg bg-[#003366] px-5 py-2 font-bold text-white disabled:opacity-50 lg:self-end">{broadcasting ? 'Broadcasting...' : 'Broadcast Notice'}</button>
        </form>
      </section>

      {loading && tickets.length === 0 ? <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-slate-500">Loading error reports...</div> : null}
      {tickets.map((ticket) => {
        const edit = editFor(ticket);
        return <article key={ticket.ticketId} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-wrap justify-between gap-2"><div><h3 className="font-bold text-slate-800">#{ticket.ticketId} - {ticket.title}</h3><p className="text-xs text-slate-500">{ticket.registrarName} - {ticket.registrarEmail}</p><p className="mt-1 text-xs font-semibold text-indigo-700">Assigned to: {ticket.assignedSpecialistLabel || 'Unassigned'}</p></div><span className="h-fit rounded-full bg-blue-100 px-2 py-1 text-xs font-bold text-blue-800">{ticket.status}</span></div>
          <p className="my-3 whitespace-pre-wrap text-sm text-slate-700">{ticket.description}</p>
          <div className="grid gap-3 lg:grid-cols-[190px_minmax(260px,1fr)_minmax(260px,2fr)_auto]">
            <select value={edit.status} onChange={(event) => changeEdit(ticket, 'status', event.target.value)} className="rounded-lg border border-slate-300 px-3 py-2"><option value="OPEN">Open</option><option value="IN_PROGRESS">In Progress</option><option value="RESOLVED">Resolved</option><option value="CLOSED">Closed</option></select>
            <SupportAssignmentSelect value={edit.assignment} onChange={(assignment) => changeEdit(ticket, 'assignment', assignment)} specialists={specialists} className="rounded-lg border border-slate-300 px-3 py-2" ariaLabel={`Support assignment for ticket ${ticket.ticketId}`} />
            <textarea rows="2" placeholder="Administrator response" value={edit.adminResponse} onChange={(event) => changeEdit(ticket, 'adminResponse', event.target.value)} className="rounded-lg border border-slate-300 px-3 py-2" />
            <button type="button" onClick={() => save(ticket)} disabled={savingTicketId === ticket.ticketId} className="rounded-lg bg-[#003366] px-4 py-2 font-bold text-white disabled:opacity-50">{savingTicketId === ticket.ticketId ? 'Saving...' : 'Save'}</button>
          </div>
        </article>;
      })}
      {!loading && tickets.length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 bg-white p-10 text-center text-slate-500">No Registrar tickets.</div> : null}
    </div>
  );
};

export default SupportTicketManagement;
