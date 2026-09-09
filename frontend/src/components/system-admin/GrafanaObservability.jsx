import React, { useEffect, useState } from 'react';
import { createSystemAdminGrafanaSession } from '../../services/api';

const dashboards = [
  { uid: 'blockgo-kubernetes-memory', label: 'Kubernetes Memory' },
  { uid: 'blockgo-api-observability', label: 'API Errors & Latency' },
  { uid: 'blockgo-fabric', label: 'Fabric Network' },
  { uid: 'blockgo-postgresql', label: 'PostgreSQL' },
  { uid: 'blockgo-workflows', label: 'BlockGO Workflows' },
  { uid: 'blockgo-logs', label: 'Logs' },
];

function dashboardUrl(baseUrl, uid) {
  const slug = uid.replace(/^blockgo-/, '');
  return `${baseUrl}d/${uid}/${slug}?orgId=1&kiosk&theme=light`;
}

function GrafanaObservability() {
  const [baseUrl, setBaseUrl] = useState('');
  const [frameUrl, setFrameUrl] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const openSession = async () => {
      setLoading(true);
      setError('');
      try {
        const response = await createSystemAdminGrafanaSession();
        if (!active) return;
        const nextBaseUrl = response?.url || '/api/SystemMonitoring/grafana/';
        setBaseUrl(nextBaseUrl);
        setFrameUrl(dashboardUrl(nextBaseUrl, dashboards[0].uid));
      } catch (requestError) {
        if (active) setError(requestError.message || 'Grafana could not be opened.');
      } finally {
        if (active) setLoading(false);
      }
    };
    openSession();
    return () => { active = false; };
  }, []);

  return (
    <div className="space-y-4">
      <div className="border-b border-slate-300 pb-4">
        <p className="text-xs font-bold uppercase text-slate-500">System Admin Only</p>
        <h2 className="mt-1 text-2xl font-bold text-[#003366]">Grafana Observability</h2>
        
      </div>

      <div className="flex flex-wrap gap-2" aria-label="Grafana dashboards">
        {dashboards.map((dashboard) => (
          <button
            key={dashboard.uid}
            type="button"
            disabled={!baseUrl}
            onClick={() => setFrameUrl(dashboardUrl(baseUrl, dashboard.uid))}
            className="rounded-md border border-blue-200 bg-white px-3 py-2 text-sm font-bold text-[#003366] transition hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {dashboard.label}
          </button>
        ))}
      </div>

      {error ? (
        <div className="rounded-md border border-red-300 bg-red-50 p-4 text-sm font-semibold text-red-800">{error}</div>
      ) : loading ? (
        <div className="flex min-h-[65vh] items-center justify-center rounded-md border border-slate-200 bg-white text-sm font-semibold text-slate-600">
          Opening protected Grafana session...
        </div>
      ) : (
        <iframe
          key={frameUrl}
          src={frameUrl}
          title="BlockGO Grafana observability dashboards"
          className="h-[74vh] min-h-[640px] w-full rounded-md border border-slate-300 bg-white shadow-sm"
          referrerPolicy="same-origin"
        />
      )}
    </div>
  );
}

export default GrafanaObservability;
