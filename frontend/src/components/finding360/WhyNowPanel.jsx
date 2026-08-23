import React, { useState } from 'react';
import { generateWhyNowReasons } from '../../utils/whyNow';
import { X } from 'lucide-react';

export default function WhyNowDrawer({ finding, onClose }) {
  const reasons = generateWhyNowReasons(finding);

  const ICONS = {
    KEV:              '🚨',
    EPSS:             '📈',
    EXPLOIT:          '💥',
    CRITICAL_ASSET:   '🏛️',
    INTERNET:         '🌐',
    SCANNER_CONSENSUS:'🔍',
    SLA_BREACHED:     '⏰',
    SLA_AT_RISK:      '⚠️',
  };

  const sources = ['Threat Intelligence', 'Asset Context', 'Scanner Consensus', 'SLA Automation'];

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" aria-label="Why Now intelligence briefing">
        <div className="drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div className="drawer-title">Why Now?</div>
              <div className="drawer-subtitle">Evidence-backed urgency · {reasons.length} active condition{reasons.length !== 1 ? 's' : ''}</div>
            </div>
            <button
              id="why-now-close"
              onClick={onClose}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
            >
              <X size={20} />
            </button>
          </div>
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {reasons.map(r => (
              <span
                key={r.id}
                className={`chip ${r.severity === 'critical' ? 'chip-critical' : r.severity === 'warning' ? 'chip-high' : 'chip-blue'}`}
              >
                {ICONS[r.id] ?? '•'} {r.label}
              </span>
            ))}
          </div>
        </div>

        <div className="drawer-body">
          {reasons.length === 0 ? (
            <div style={{ fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic', textAlign: 'center', padding: 'var(--space-6)' }}>
              No urgent conditions detected for this finding.
            </div>
          ) : (
            reasons.map(r => (
              <div key={r.id} id={`why-now-reason-${r.id}`} className={`drawer-reason-item severity-${r.severity}`}>
                <div className="drawer-reason-icon">{ICONS[r.id] ?? '•'}</div>
                <div>
                  <div className="drawer-reason-label">{r.label}</div>
                  <div className="drawer-reason-evidence">{r.evidence}</div>
                </div>
              </div>
            ))
          )}

          {/* Recommended Action */}
          {finding.recommended_action && (
            <div style={{ marginTop: 'var(--space-4)' }}>
              <div className="drawer-section-title">Recommended Action</div>
              <div style={{
                marginTop: 'var(--space-2)',
                padding: 'var(--space-4)',
                background: 'var(--bg-periwinkle)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-blue)',
                fontSize: 13,
                fontWeight: 600,
                color: 'var(--color-purple)',
              }}>
                {finding.recommended_action}
              </div>
            </div>
          )}

          {/* Evidence Sources */}
          <div style={{ marginTop: 'var(--space-4)', paddingTop: 'var(--space-4)', borderTop: '1px solid var(--border-light)' }}>
            <div className="drawer-section-title" style={{ marginBottom: 10 }}>Evidence Sources</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {sources.map(src => (
                <span key={src} className="chip chip-lavender">{src}</span>
              ))}
            </div>
          </div>

          <p style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 'var(--space-4)', lineHeight: 1.6 }}>
            Every reason shown is derived from actual security data in the vulnerability record. No reasons are fabricated.
          </p>
        </div>
      </aside>
    </>
  );
}
