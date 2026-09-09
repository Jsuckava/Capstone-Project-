import React, { useCallback, useEffect, useRef, useState } from 'react';
import { fetchSystemMonitoringSummary, resolveSecurityEvent } from '../../services/api';

const REFRESH_INTERVAL_MS = 30000;

const statusStyles = {
  healthy: 'border-emerald-300 bg-emerald-50 text-emerald-800',
  warning: 'border-amber-300 bg-amber-50 text-amber-800',
  down: 'border-red-300 bg-red-50 text-red-800',
  not_configured: 'border-slate-300 bg-slate-100 text-slate-700',
  checking: 'border-blue-200 bg-blue-50 text-blue-800',
};

const viewTitles = {
  overview: 'System Overview',
  infrastructure: 'Infrastructure & Data',
  alerts: 'Active Alerts',
};

const formatDateTime = (value) => {
  if (!value) return 'Not checked';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Not checked' : date.toLocaleString();
};

const formatBytes = (value) => {
  if (value === null || value === undefined || value === '') return '--';
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return '--';
  if (numericValue === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const unitIndex = Math.min(Math.floor(Math.log(numericValue) / Math.log(1024)), units.length - 1);
  return `${(numericValue / (1024 ** unitIndex)).toFixed(unitIndex > 1 ? 1 : 0)} ${units[unitIndex]}`;
};

const formatDuration = (seconds) => {
  if (seconds === null || seconds === undefined || seconds === '') return '--';
  const totalSeconds = Number(seconds);
  if (!Number.isFinite(totalSeconds)) return '--';
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
};

const formatMetric = (value, fractionDigits = 0) => {
  if (value === null || value === undefined || value === '') return '--';
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue.toFixed(fractionDigits) : '--';
};

function StatusBadge({ status = 'checking', label }) {
  const normalizedStatus = String(status || 'checking').toLowerCase();
  return (
    <span className={`inline-flex min-h-7 items-center rounded-full border px-3 py-1 text-xs font-bold capitalize ${statusStyles[normalizedStatus] || statusStyles.warning}`}>
      {label || normalizedStatus.replaceAll('_', ' ')}
    </span>
  );
}

function Metric({ label, value, tone = 'default' }) {
  const toneClasses = {
    healthy: 'border-emerald-300 text-emerald-800',
    warning: 'border-amber-300 text-amber-800',
    down: 'border-red-300 text-red-800',
    default: 'border-slate-200 text-slate-900',
  };

  return (
    <article className={`min-h-24 rounded-md border bg-white p-4 shadow-sm ${toneClasses[tone] || toneClasses.default}`}>
      <p className="text-xs font-bold uppercase text-slate-500">{label}</p>
      <p className="mt-2 break-words text-2xl font-bold">{value}</p>
    </article>
  );
}

function AlertsTable({ alerts, metricsAvailable, onResolve }) {
  if (!alerts.length) {
    return (
      <p className="p-5 text-sm text-slate-600">
        {metricsAvailable ? 'No active Prometheus alerts.' : 'Alert data is unavailable until Prometheus is configured and ready.'}
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs font-bold uppercase text-slate-500">
          <tr>
            <th className="px-4 py-3">Alert</th>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Component</th>
            <th className="px-4 py-3">Summary</th>
            <th className="px-4 py-3">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {alerts.map((alert, index) => (
            <tr key={`${alert.name}-${alert.component}-${index}`} className="align-top">
              <td className="px-4 py-4 font-bold text-slate-900">{alert.name}</td>
              <td className="px-4 py-4"><StatusBadge status={alert.severity === 'critical' ? 'down' : 'warning'} label={alert.severity} /></td>
              <td className="px-4 py-4 text-slate-700">{alert.component}</td>
              <td className="max-w-xl px-4 py-4 text-slate-700">{alert.summary}</td>
              <td className="px-4 py-4">{alert.eventId ? <button type="button" onClick={() => onResolve?.(alert.eventId)} className="rounded-md bg-slate-800 px-3 py-2 text-xs font-bold text-white">Resolve</button> : <span className="text-xs text-slate-400">Managed by Prometheus</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SystemMonitoring({ activeView = 'overview' }) {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const activeRequest = useRef(null);

  const refresh = useCallback(async () => {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setIsRefreshing(true);
    setError('');

    try {
      const nextSummary = await fetchSystemMonitoringSummary({ signal: controller.signal });
      if (activeRequest.current === controller) setSummary(nextSummary);
    } catch (requestError) {
      if (requestError.name !== 'AbortError' && activeRequest.current === controller) {
        setError(requestError.message || 'System monitoring could not be loaded.');
      }
    } finally {
      if (activeRequest.current === controller) setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const intervalId = window.setInterval(refresh, REFRESH_INTERVAL_MS);
    return () => {
      window.clearInterval(intervalId);
      activeRequest.current?.abort();
    };
  }, [refresh]);

  const alerts = summary?.alerts || [];
  const runtime = summary?.runtime || {};
  const database = summary?.database || {};
  const infrastructure = summary?.infrastructure || {};
  const metricsAvailable = infrastructure.source === 'prometheus';
  const overallStatus = summary?.status || (isRefreshing ? 'checking' : 'warning');
  const resolveEvent = async (eventId) => {
    try { await resolveSecurityEvent(eventId); await refresh(); }
    catch (requestError) { setError(requestError.message || 'Security event could not be resolved.'); }
  };

  const overview = (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Metric label="Overall" value={overallStatus.replaceAll('_', ' ')} tone={overallStatus} />
        <Metric label="Active Alerts" value={metricsAvailable ? alerts.length : '--'} tone={alerts.length ? 'warning' : 'default'} />
        <Metric label="Backend Uptime" value={formatDuration(runtime.uptimeSeconds)} />
      </div>

      <section className="overflow-hidden rounded-md border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 px-5 py-4">
          <h3 className="text-base font-bold text-[#003366]">Current Alerts</h3>
        </div>
        <AlertsTable alerts={alerts.slice(0, 5)} metricsAvailable={metricsAvailable} onResolve={resolveEvent} />
      </section>
    </div>
  );

  const infrastructureView = (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Process Memory" value={formatBytes(runtime.workingSetBytes)} />
        <Metric label="Managed Memory" value={formatBytes(runtime.managedMemoryBytes)} />
        <Metric label="Process Threads" value={formatMetric(runtime.threadCount)} />
        <Metric label="CPU Capacity" value={`${formatMetric(runtime.processorCount)} cores`} />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <section className="rounded-md border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-5 py-4">
            <h3 className="text-base font-bold text-[#003366]">PostgreSQL</h3>
          </div>
          <dl className="divide-y divide-slate-100 px-5 text-sm">
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Status</dt><dd><StatusBadge status={database.status} /></dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Database</dt><dd className="font-semibold text-slate-900">{database.name || '--'}</dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Size</dt><dd className="font-semibold text-slate-900">{formatBytes(database.sizeBytes)}</dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Active connections</dt><dd className="font-semibold text-slate-900">{formatMetric(database.activeConnections)}</dd></div>
          </dl>
        </section>

        <section className="rounded-md border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-5 py-4">
            <h3 className="text-base font-bold text-[#003366]">Prometheus Metrics</h3>
          </div>
          <dl className="divide-y divide-slate-100 px-5 text-sm">
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Source</dt><dd className="font-semibold capitalize text-slate-900">{String(infrastructure.source || 'unavailable').replaceAll('_', ' ')}</dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">CPU usage</dt><dd className="font-semibold text-slate-900">{formatMetric(infrastructure.cpuCores, 2)} cores</dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Memory usage</dt><dd className="font-semibold text-slate-900">{formatBytes(infrastructure.memoryBytes)}</dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Running pods</dt><dd className="font-semibold text-slate-900">{formatMetric(infrastructure.runningPods)}</dd></div>
            <div className="flex justify-between gap-4 py-4"><dt className="text-slate-500">Healthy Fabric targets</dt><dd className="font-semibold text-slate-900">{formatMetric(infrastructure.healthyFabricTargets)}</dd></div>
          </dl>
        </section>
      </div>
    </div>
  );

  const alertView = (
    <section className="overflow-hidden rounded-md border border-slate-200 bg-white shadow-sm">
      <AlertsTable alerts={alerts} metricsAvailable={metricsAvailable} onResolve={resolveEvent} />
    </section>
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 border-b border-slate-300 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-bold uppercase text-slate-500">System Monitoring</p>
          <div className="mt-1 flex flex-wrap items-center gap-3">
            <h2 className="text-2xl font-bold text-[#003366]">{viewTitles[activeView] || viewTitles.overview}</h2>
            <StatusBadge status={overallStatus} />
          </div>
          <p className="mt-2 text-sm text-slate-500">Last updated: {formatDateTime(summary?.generatedAt)}</p>
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={isRefreshing}
          className="min-h-11 rounded-md bg-[#003366] px-5 py-2 text-sm font-semibold text-white transition hover:bg-blue-950 disabled:cursor-not-allowed disabled:bg-slate-400"
        >
          {isRefreshing ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-md border border-red-300 bg-red-50 px-4 py-3 text-sm font-semibold text-red-800">
          {error}
        </div>
      )}

      {!summary && isRefreshing ? (
        <div className="rounded-md border border-slate-200 bg-white p-8 text-center text-sm font-semibold text-slate-600 shadow-sm">
          Loading system status...
        </div>
      ) : activeView === 'infrastructure' ? infrastructureView
          : activeView === 'alerts' ? alertView
            : overview}
    </div>
  );
}

export default SystemMonitoring;
