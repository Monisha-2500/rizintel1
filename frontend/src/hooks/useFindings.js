import { useState, useEffect } from 'react';
import { getFindings, getScanRunFindings } from '../services/findingsService';
import { sortFindings } from '../utils/priorityQueue';

export function useFindings(scanRunId = null, orgId = null) {
  const [findings, setFindings]   = useState([]);
  const [loading,  setLoading]    = useState(true);
  const [error,    setError]      = useState(null);

  useEffect(() => {
    let cancelled = false;

    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        let rawFindings = [];
        if (scanRunId && orgId) {
          const scoped = await getScanRunFindings(orgId, scanRunId);
          rawFindings = scoped.findings || [];
        } else if (orgId || scanRunId) {
          rawFindings = await getFindings({ org_id: orgId, scan_run_id: scanRunId });
        } else {
          rawFindings = await getFindings();
        }
        if (!cancelled) {
          setFindings(sortFindings(rawFindings));
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to load findings');
          setLoading(false);
        }
      }
    };

    loadData();

    const handleModeChange = () => {
      loadData();
    };

    window.addEventListener('rizintel-datamode-change', handleModeChange);
    return () => {
      cancelled = true;
      window.removeEventListener('rizintel-datamode-change', handleModeChange);
    };
  }, [scanRunId, orgId]);

  return { findings, loading, error };
}
