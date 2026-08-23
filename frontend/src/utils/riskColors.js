/* riskColors.js — color helpers for chart libraries (Recharts) that can't use CSS vars */

export const RISK_COLORS = {
  CRITICAL: '#DC2626',
  HIGH:     '#EA580C',
  MEDIUM:   '#D97706',
  LOW:      '#16A34A',
};

export const RISK_DISTRIBUTION_COLORS = {
  CRITICAL: '#DC2626',
  HIGH:     '#EA580C',
  MEDIUM:   '#D97706',
  LOW:      '#16A34A',
};

export const SLA_COLORS = {
  BREACHED: '#DC2626',
  AT_RISK:  '#D97706',
  ON_TRACK: '#16A34A',
  MET:      '#5B7CFA',
};

/** Returns CSS class suffix for a risk level */
export function riskLevelClass(level) {
  const l = (level ?? '').toUpperCase();
  if (l === 'CRITICAL') return 'critical';
  if (l === 'HIGH')     return 'high';
  if (l === 'MEDIUM')   return 'medium';
  return 'low';
}

/** Hex color for chart use */
export function riskColor(level) {
  return RISK_COLORS[(level ?? '').toUpperCase()] ?? '#9B8AFB';
}
