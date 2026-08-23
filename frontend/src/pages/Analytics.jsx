import React from 'react';
import { useFindings } from '../hooks/useFindings';
import AnalyticsCharts from '../components/analytics/AnalyticsCharts';

export default function Analytics() {
  const { findings, loading, error } = useFindings();

  if (loading) return <div className="empty-state">Loading Analytics...</div>;
  if (error) return <div className="empty-state">Error loading findings: {error}</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <AnalyticsCharts findings={findings} />
    </div>
  );
}
