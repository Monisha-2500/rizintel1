import React from 'react';
import { TrendingUp } from 'lucide-react';

export default function RiskDelta({ delta }) {
  if (!delta) return (
    <div className="card">
      <div className="card-header"><div className="card-title">Risk Evolution</div></div>
      <div className="card-body">
        <div className="empty-state" style={{ padding: 'var(--space-5)' }}>
          <div className="empty-state-icon">📊</div>
          <h3>No delta data available</h3>
        </div>
      </div>
    </div>
  );

  const increased = delta.delta > 0;

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Risk Evolution</div>
          <div className="card-subtitle">What changed since last assessment</div>
        </div>
        {increased && (
          <span className="chip chip-critical">
            <TrendingUp size={11} /> Risk Increased
          </span>
        )}
      </div>
      <div className="card-body">
        {/* Score track */}
        <div className="risk-delta-track">
          <div className="risk-delta-score">
            <div className="risk-delta-num" style={{ color: 'var(--text-muted)' }}>
              {delta.previous_score ?? '—'}
            </div>
            <div className="risk-delta-lbl">Previous</div>
          </div>

          <div className="risk-delta-arrow-line" />

          <div className="risk-delta-score">
            <div className="risk-delta-num" style={{ color: 'var(--text-primary)' }}>
              {delta.current_score ?? '—'}
            </div>
            <div className="risk-delta-lbl">Current</div>
          </div>

          <div style={{ width: 1, background: 'var(--border-color)', height: 40 }} />

          <div className="risk-delta-change">
            <div className="risk-delta-change-num" style={{ color: increased ? 'var(--risk-critical)' : 'var(--risk-low)' }}>
              {increased ? '+' : ''}{delta.delta}
            </div>
            <div className="risk-delta-change-lbl">{increased ? 'Increase' : 'Decrease'}</div>
          </div>
        </div>

        {/* Changed Factors */}
        {(delta.changed_factors ?? []).length > 0 && (
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.8px', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
              What Changed
            </div>
            <div className="risk-delta-factors">
              {delta.changed_factors.map((f, i) => (
                <div key={i} className="risk-delta-factor">
                  <div className="risk-delta-factor-label">
                    {(f.factor ?? '').replace(/_/g, ' ')}
                  </div>
                  <div className="risk-delta-factor-change">
                    <span className="risk-delta-from">{String(f.from ?? f.from_val ?? '—')}</span>
                    <span style={{ color: 'var(--text-muted)' }}>→</span>
                    <span className="risk-delta-to">{String(f.to ?? f.to_val ?? '—')}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {increased && (delta.changed_factors ?? []).length > 0 && (
          <div style={{
            marginTop: 'var(--space-4)',
            padding: 'var(--space-3) var(--space-4)',
            background: 'var(--risk-critical-lt)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--risk-critical-bdr)',
            fontSize: 12,
            color: 'var(--risk-critical)',
            fontWeight: 500,
          }}>
            Risk increased because threat context changed.
          </div>
        )}
      </div>
    </div>
  );
}
