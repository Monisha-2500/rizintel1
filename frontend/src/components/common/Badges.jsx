import React from 'react';

/* ── Risk Level ─────────────────────────────────────────────────────────── */
export function riskClass(level) {
  const l = (level ?? '').toUpperCase();
  if (l === 'CRITICAL') return 'critical';
  if (l === 'HIGH')     return 'high';
  if (l === 'MEDIUM')   return 'medium';
  return 'low';
}

export function RiskBadge({ level }) {
  if (!level) return <span className="badge badge-low">—</span>;
  return <span className={`badge badge-${riskClass(level)}`}>{level}</span>;
}

export function RiskPill({ score, level }) {
  const cls = riskClass(level ?? (score >= 85 ? 'CRITICAL' : score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'));
  return <span className={`risk-pill ${cls}`}>{score ?? '—'}</span>;
}

export function RiskScoreBubble({ score, level, size = 52 }) {
  const cls = riskClass(level ?? (score >= 85 ? 'CRITICAL' : score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'));
  const fontSize = size >= 52 ? 18 : size >= 40 ? 14 : 11;
  return (
    <div
      className={`risk-score-bubble ${cls}`}
      style={{ width: size, height: size, fontSize }}
    >
      {score ?? '—'}
    </div>
  );
}

export function ConfidenceBadge({ classification }) {
  const map = {
    CONFIRMED:        'badge badge-confirmed',
    HIGH_CONFIDENCE:  'badge badge-high-confidence',
    NEEDS_REVIEW:     'badge badge-needs-review',
    LIKELY_NOISE:     'badge badge-likely-noise',
  };
  const labelMap = {
    CONFIRMED:       'Confirmed',
    HIGH_CONFIDENCE: 'High Confidence',
    NEEDS_REVIEW:    'Needs Review',
    LIKELY_NOISE:    'Likely Noise',
  };
  const key = (classification ?? '').toUpperCase();
  return <span className={map[key] ?? 'badge badge-likely-noise'}>{labelMap[key] ?? classification ?? '—'}</span>;
}

export function SLABadge({ status }) {
  const map = {
    BREACHED: 'badge badge-sla-breached',
    AT_RISK:  'badge badge-sla-at-risk',
    ON_TRACK: 'badge badge-sla-on-track',
    MET:      'badge badge-sla-met',
  };
  const key = (status ?? '').toUpperCase();
  return <span className={map[key] ?? 'badge badge-sla-on-track'}>{status ?? '—'}</span>;
}

export function KEVBadge({ listed }) {
  return listed
    ? <span className="badge badge-kev">KEV</span>
    : <span className="badge badge-no-kev">—</span>;
}

export function WorkflowBadge({ status }) {
  const map = {
    OPEN:        'badge badge-open',
    IN_PROGRESS: 'badge badge-in-progress',
    RESOLVED:    'badge badge-resolved',
    CLOSED:      'badge badge-closed',
  };
  const labelMap = { OPEN: 'Open', IN_PROGRESS: 'In Progress', RESOLVED: 'Resolved', CLOSED: 'Closed' };
  const key = (status ?? '').toUpperCase();
  return <span className={map[key] ?? 'badge badge-open'}>{labelMap[key] ?? status ?? '—'}</span>;
}

export function BooleanBadge({ value, trueLabel = 'Yes', falseLabel = 'No', dangerOnTrue = false }) {
  if (value === true) {
    return <span className={`badge ${dangerOnTrue ? 'badge-high' : 'badge-sla-on-track'}`}>{trueLabel}</span>;
  }
  return <span className="badge badge-no-kev">{falseLabel}</span>;
}

/* Also export riskLevelClass for backward-compat */
export const riskLevelClass = riskClass;
