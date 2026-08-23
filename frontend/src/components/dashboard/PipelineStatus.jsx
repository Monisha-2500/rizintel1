import React from 'react';
import { CheckCircle, Circle, ArrowRight } from 'lucide-react';

const MODULES = [
  { id: 'M1', label: 'Normalization',    status: 'mock' },
  { id: 'M2', label: 'Deduplication',   status: 'mock' },
  { id: 'M3', label: 'Confidence',       status: 'mock' },
  { id: 'M4', label: 'Threat Intel',     status: 'mock' },
  { id: 'M5', label: 'Risk Scoring',     status: 'mock' },
  { id: 'M6', label: 'Explainability',   status: 'mock' },
  { id: 'M7', label: 'SLA Automation',   status: 'mock' },
  { id: 'M8', label: 'Command Center',   status: 'active' },
];

export default function PipelineStatus() {
  return (
    <div className="card" style={{ marginBottom: 'var(--space-5)' }}>
      <div className="card-header">
        <div>
          <div className="card-title">Pipeline Status</div>
          <div className="card-subtitle">M1 → M8 intelligence pipeline</div>
        </div>
        <span className="badge badge-sla-on-track" style={{ fontSize: 11 }}>
          <span className="status-dot" style={{ background: '#16A34A' }} />
          M8 Operational
        </span>
      </div>
      <div className="card-body" style={{ paddingTop: 'var(--space-3)' }}>
        <div className="pipeline-strip">
          {MODULES.map((m, i) => (
            <React.Fragment key={m.id}>
              <div
                id={`pipeline-${m.id.toLowerCase()}`}
                className={`pipeline-node ${m.status}`}
                title={m.status === 'mock' ? 'Running with mock data' : 'Operational'}
              >
                {m.status === 'active'
                  ? <CheckCircle size={12} />
                  : <Circle size={12} />
                }
                <span style={{ fontWeight: 700 }}>{m.id}</span>
                <span style={{ fontWeight: 400 }}>{m.label}</span>
              </div>
              {i < MODULES.length - 1 && (
                <span className="pipeline-arrow">
                  <ArrowRight size={12} />
                </span>
              )}
            </React.Fragment>
          ))}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 'var(--space-3)' }}>
          M1–M7 are consuming mock data. M8 is operational. Integration endpoints are ready for live API swap.
        </div>
      </div>
    </div>
  );
}
