import { useState, useEffect } from 'react';
import { getFindings } from '../services/findingsService';
import { sortFindings } from '../utils/priorityQueue';

export function useFindings() {
  const [findings, setFindings]   = useState([]);
  const [loading,  setLoading]    = useState(true);
  const [error,    setError]      = useState(null);

  useEffect(() => {
    let cancelled = false;

    const loadData = () => {
      setLoading(true);
      getFindings()
        .then(data => {
          if (!cancelled) {
            setFindings(sortFindings(data));
            setLoading(false);
          }
        })
        .catch(err => {
          if (!cancelled) {
            setError(err.message);
            setLoading(false);
          }
        });
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

  return { findings, loading, error };
}
