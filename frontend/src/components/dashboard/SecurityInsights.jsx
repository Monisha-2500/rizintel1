import React from 'react';
import { generateInsights } from '../../utils/insights';
import { AlertTriangle, AlertCircle, Info } from 'lucide-react';

const ICONS = {
  critical: <AlertTriangle size={15} />,
  warning:  <AlertCircle  size={15} />,
  info:     <Info         size={15} />,
};

export default function SecurityInsights({ findings }) {
  const insights = generateInsights(findings ?? []);

  if (insights.length === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">Security Insights</div>
        </div>
        <div className="card-body">
          <div className="empty-state" style={{ padding: 'var(--space-6)' }}>
            <div className="empty-state-icon">✅</div>
            <h3>No urgent insights</h3>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Quick Security Insights</div>
          <div className="card-subtitle">Deterministic — calculated from live data</div>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {insights.length} insight{insights.length > 1 ? 's' : ''}
        </span>
      </div>
      <div className="card-body">
        <div className="insights-list">
          {insights.map(ins => (
            <div key={ins.id} id={`insight-${ins.id}`} className={`insight-item severity-${ins.severity}`}>
              {ICONS[ins.severity]}
              <span style={{ fontSize: 13, fontWeight: 500 }}>{ins.message}</span>
            </div>
          ))}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 'var(--space-3)' }}>
          Insights are generated deterministically from the findings dataset. No LLM or external data is used.
        </div>
      </div>
    </div>
  );
}
