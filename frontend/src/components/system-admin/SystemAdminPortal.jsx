import React, { useCallback, useEffect, useState } from 'react';
import plvlogo from '../../assets/plvlogo.png';
import { fetchSupportTickets } from '../../services/api';
import SystemMonitoring from './SystemMonitoring';
import RegistrarAccountManagement from './RegistrarAccountManagement';
import SupportTicketManagement from './SupportTicketManagement';
import GrafanaObservability from './GrafanaObservability';

const navigationItems = [
  { id: 'overview', label: 'Overview' },
  { id: 'registrars', label: 'Registrar Accounts' },
  { id: 'tickets', label: 'Error Reports' },
  { id: 'infrastructure', label: 'Infrastructure & Data' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'observability', label: 'Grafana Observability' },
];

function SystemAdminPortal({ adminData, onLogout }) {
  const [activeView, setActiveView] = useState('overview');
  const [tickets, setTickets] = useState([]);

  const loadTickets = useCallback(async () => {
    try {
      const response = await fetchSupportTickets();
      setTickets(Array.isArray(response?.data) ? response.data : []);
    } catch {
      setTickets([]);
    }
  }, []);

  useEffect(() => { loadTickets(); }, [loadTickets]);

  const openTickets = tickets.filter((ticket) => ['OPEN', 'IN_PROGRESS'].includes(ticket.status));
  const recentTickets = tickets.slice(0, 3);

  return (
    <div className="fixed inset-0 z-[100] flex min-h-screen flex-col overflow-hidden bg-slate-100 text-slate-900">
      <header
        className="shrink-0 border-b-2 border-yellow-400 bg-[#001b55] text-white shadow-sm"
        style={{ backgroundImage: "linear-gradient(118deg, transparent 0 48%, rgba(10,48,122,.72) 48.2% 62%, transparent 62.2%), linear-gradient(142deg, transparent 0 68%, rgba(0,43,112,.85) 68.2% 83%, transparent 83.2%), linear-gradient(105deg, #00113f 0%, #002469 54%, #001748 100%)" }}
      >
        <div className="flex min-h-[72px] items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-white">
              <img src={plvlogo} alt="PLV Logo" className="h-10 w-10 object-contain" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase text-blue-100">PLV BlockGO</p>
              <h1 className="truncate text-lg font-bold sm:text-xl">System Administration</h1>
            </div>
          </div>

          <div className="flex min-w-0 items-center gap-3">
            <div className="hidden min-w-0 text-right md:block">
              <p className="truncate text-sm font-semibold">{adminData?.name || 'System Administrator'}</p>
              <p className="truncate text-xs text-blue-100">{adminData?.email || ''}</p>
            </div>
            <button
              type="button"
              onClick={onLogout}
              className="rounded-md border border-yellow-400 px-4 py-2 text-sm font-semibold text-yellow-300 transition hover:bg-yellow-400 hover:text-[#003366]"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <aside className="shrink-0 border-b border-slate-200 bg-white p-3 lg:w-60 lg:border-b-0 lg:border-r lg:p-4">
          <nav className="flex gap-2 overflow-x-auto lg:flex-col" aria-label="System administration views">
            {navigationItems.map((item) => {
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveView(item.id)}
                  className={`min-h-11 shrink-0 rounded-md border-l-4 px-4 py-2 text-left text-sm font-semibold transition lg:w-full ${
                    isActive
                      ? 'border-yellow-400 bg-[#003366] text-white'
                      : 'border-transparent text-slate-700 hover:bg-slate-100'
                  }`}
                >
                {item.label}
                </button>
              );
            })}
          </nav>
        </aside>

        <main className="min-w-0 flex-1 overflow-y-auto p-4 sm:p-6">
          <div className="mx-auto w-full max-w-[1500px]">
            {activeView === 'registrars' ? (
              <RegistrarAccountManagement />
            ) : activeView === 'tickets' ? (
              <SupportTicketManagement />
            ) : activeView === 'observability' ? (
              <GrafanaObservability />
            ) : (
              <>
                <SystemMonitoring activeView={activeView} />
                {activeView === 'overview' ? (
                  <section className="mt-5 rounded-md border border-slate-200 bg-white p-5 shadow-sm">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-xs font-bold uppercase text-slate-500">Registrar Support</p>
                        <h2 className="mt-1 text-xl font-bold text-[#003366]">System Error Reports</h2>
                        
                      </div>
                      <button type="button" onClick={() => setActiveView('tickets')} className="rounded-md bg-[#003366] px-4 py-2 text-sm font-bold text-white">View Error Reports</button>
                    </div>
                    <div className="mt-5 grid gap-3 sm:grid-cols-3">
                      <div className="rounded-md border border-amber-200 bg-amber-50 p-4"><p className="text-xs font-bold uppercase text-amber-700">Needs attention</p><p className="mt-1 text-2xl font-bold text-amber-900">{openTickets.length}</p></div>
                      <div className="rounded-md border border-blue-200 bg-blue-50 p-4"><p className="text-xs font-bold uppercase text-blue-700">Recent reports</p><p className="mt-1 text-2xl font-bold text-blue-900">{tickets.length}</p></div>
                      <div className="rounded-md border border-emerald-200 bg-emerald-50 p-4"><p className="text-xs font-bold uppercase text-emerald-700">Resolved / closed</p><p className="mt-1 text-2xl font-bold text-emerald-900">{tickets.filter((ticket) => ['RESOLVED', 'CLOSED'].includes(ticket.status)).length}</p></div>
                    </div>
                    <div className="mt-5 space-y-2">{recentTickets.length ? recentTickets.map((ticket) => <button type="button" key={ticket.ticketId} onClick={() => setActiveView('tickets')} className="flex w-full items-center justify-between gap-3 rounded-md border border-slate-200 p-3 text-left hover:bg-slate-50"><span className="min-w-0"><span className="block truncate font-bold text-slate-800">#{ticket.ticketId} · {ticket.title}</span><span className="block text-xs text-slate-500">{ticket.registrarName} · {ticket.severity}</span></span><span className="shrink-0 rounded-full bg-blue-100 px-2 py-1 text-xs font-bold text-blue-800">{ticket.status}</span></button>) : <p className="rounded-md border border-dashed border-slate-300 p-5 text-center text-sm text-slate-500">No Registrar error reports yet.</p>}</div>
                  </section>
                ) : null}
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

export default SystemAdminPortal;
