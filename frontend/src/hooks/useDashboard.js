import { useState, useEffect } from 'react';
import { getDashboardSummary } from '../services/findingsService';

export function useDashboard() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

  useEffect(() => {
    let cancelled = false;

    const loadData = () => {
      setLoading(true);
      getDashboardSummary()
        .then(data => { if (!cancelled) { setSummary(data); setLoading(false); } })
        .catch(err  => { if (!cancelled) { setError(err.message); setLoading(false); } });
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
  }, []);

  return { summary, loading, error };
}
