import React from 'react';
import { CheckCircle, Database, Zap } from 'lucide-react';

const MODULES = [
  { id: 'M1', name: 'Scanner Normalization',   desc: 'Ingestion & normalization', status: 'mock' },
  { id: 'M2', name: 'Deduplication',           desc: 'Scanner consensus',         status: 'mock' },
  { id: 'M3', name: 'Confidence Scoring',      desc: 'Noise classification',      status: 'mock' },
  { id: 'M4', name: 'Threat Intelligence',     desc: 'CVE / EPSS / KEV enrichment', status: 'mock' },
  { id: 'M5', name: 'Risk Scoring',            desc: 'Dynamic risk calculation',  status: 'mock' },
  { id: 'M6', name: 'Explainability',          desc: 'Recommendation engine',     status: 'mock' },
  { id: 'M7', name: 'SLA Automation',          desc: 'Remediation workflow',      status: 'mock' },
  { id: 'M8', name: 'Command Center',          desc: 'Visualization & operations', status: 'operational' },
];

export default function IntegrationHealth() {
  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Integration Health & Pipeline Architecture</div>
          <div className="card-subtitle">Upstream module integration status (Schema v1.0)</div>
        </div>
      </div>
      <div className="card-body">
        <div className="pipeline-flow" style={{ justifyContent: 'center' }}>
          {MODULES.map((m, i) => (
            <React.Fragment key={m.id}>
              <div
                id={`integration-mod-${m.id.toLowerCase()}`}
                className={`pipeline-module ${m.status}`}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {m.status === 'operational'
                    ? <Zap size={14} color="var(--color-teal-dk)" />
                    : <Database size={14} color="var(--color-primary)" />
                  }
                  <span className="pipeline-module-id">{m.id}</span>
                </div>
                <div className="pipeline-module-name">{m.name}</div>
                <span className={`badge ${m.status === 'operational' ? 'badge-confirmed' : 'badge-open'}`} style={{ fontSize: 9 }}>
                  {m.status === 'operational' ? 'Operational' : 'Mock Schema v1.0'}
                </span>
              </div>

              {i < MODULES.length - 1 && (
                <div className="pipeline-connector">→</div>
              )}
            </React.Fragment>
          ))}
        </div>

        <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 'var(--space-4)', textAlign: 'center', lineHeight: 1.5 }}>
          M8 sits above Modules M1–M7 and consumes their intelligence. Upstream modules currently provide Schema v1.0 mock data.
          M8 is operational and will seamlessly process live API responses when M1–M7 are attached.
        </p>
      </div>
    </div>
  );
}
