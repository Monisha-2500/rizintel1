import React from 'react';
import IntegrationHealth from '../components/integration/IntegrationHealth';
import { GitBranch, CheckCircle2, Shield, Database, FileText } from 'lucide-react';

export default function Integration() {
  return (
    <div className="stack">
      {/* Hero */}
      <div className="page-hero" style={{ padding: 'var(--space-6) var(--space-8)' }}>
        <div className="hero-eyebrow"><GitBranch size={12} /> Architecture & Pipelines</div>
        <h1 className="hero-title" style={{ fontSize: 26, marginBottom: 6 }}>
          RizIntel Intelligence Pipeline
        </h1>
        <p className="hero-subtitle" style={{ marginBottom: 0 }}>
          Trace how scanner signals flow through M1–M7 modules into M8 Command Center decision intelligence.
        </p>
      </div>

      {/* Integration Health Flow */}
      <IntegrationHealth />

      {/* Schema & Protocol Details */}
      <div className="grid-3">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Data Contract</div>
          </div>
          <div className="card-body stack-3">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <FileText size={18} color="var(--color-primary)" />
              <div>
                <div style={{ fontWeight: 700, fontSize: 13 }}>Schema v1.0 Contract</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>m8_input_schema.json</div>
              </div>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Strict JSON Schema validation powered by Pydantic models in FastAPI backend.
              All upstream fields are preserved without breaking existing contracts.
            </p>
            <span className="badge badge-confirmed" style={{ width: 'fit-content' }}>
              Contract Active
            </span>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Data Validation</div>
          </div>
          <div className="card-body stack-3">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <CheckCircle2 size={18} color="var(--color-teal-dk)" />
              <div>
                <div style={{ fontWeight: 700, fontSize: 13 }}>Strict Pydantic Validation</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Backend Layer</div>
              </div>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Malformed or incomplete payloads are validated before reaching the UI layer.
            </p>
            <span className="badge badge-confirmed" style={{ width: 'fit-content' }}>
              Validation Passed
            </span>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Pipeline Health</div>
          </div>
          <div className="card-body stack-3">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={18} color="var(--color-purple)" />
              <div>
                <div style={{ fontWeight: 700, fontSize: 13 }}>M8 Operational Status</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Command Center Layer</div>
              </div>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              M8 sits above M1–M7 and never recalculates upstream outputs. All scores, classifications, and explanations are visualized accurately.
            </p>
            <span className="badge badge-confirmed" style={{ width: 'fit-content' }}>
              M8 Operational
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
