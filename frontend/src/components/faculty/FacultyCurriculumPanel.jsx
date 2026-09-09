import React, { useCallback, useEffect, useState } from 'react';
import { fetchFacultyCurriculums } from '../../services/api';
import CurriculumViewer from '../shared/CurriculumViewer';

const FacultyCurriculumPanel = () => {
  const [curricula, setCurricula] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetchFacultyCurriculums();
      setCurricula(Array.isArray(response?.data) ? response.data : []);
    } catch (requestError) {
      setError(requestError.message || 'Unable to load the curriculum checklist.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-[#003366]">Program Curriculum</h2>
          
        </div>
        <button type="button" onClick={load} className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-700">
          Refresh
        </button>
      </div>
      {error ? <div className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
      <CurriculumViewer curricula={curricula} loading={loading} emptyMessage="No published curriculum matches your assigned programs." />
    </div>
  );
};

export default FacultyCurriculumPanel;
