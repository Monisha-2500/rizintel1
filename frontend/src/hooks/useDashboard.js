import { useState, useEffect } from 'react';
import { getDashboardSummary, getScanRunFindings } from '../services/findingsService';

export function useDashboard(scanRunId = null, orgId = null) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

  useEffect(() => {
    let cancelled = false;

    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        if (scanRunId && orgId) {
          const scoped = await getScanRunFindings(orgId, scanRunId);
          if (!cancelled) {
            setSummary({ summary: scoped.summary || {} });
            setLoading(false);
          }
        } else {
          const data = await getDashboardSummary();
          if (!cancelled) {
            setSummary(data);
            setLoading(false);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to load dashboard summary');
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

  return { summary, loading, error };
}
