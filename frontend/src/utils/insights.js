/**
 * insights.js — Quick Security Insights Generator
 *
 * Generates deterministic analyst-facing insight messages from findings.
 * Only emits insights supported by actual data — never fabricated.
 * No LLM calls. Pure computation over the findings array.
 */

/**
 * generateInsights(findings) → [{ id, message, severity }]
 * severity: 'critical' | 'warning' | 'info'
 */
export function generateInsights(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];

  const insights = [];

  // Count critical findings
  const criticalFindings = findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'CRITICAL');
  if (criticalFindings.length > 0) {
    insights.push({
      id: 'CRITICAL_COUNT',
      message: `${criticalFindings.length} critical finding${criticalFindings.length > 1 ? 's' : ''} require${criticalFindings.length === 1 ? 's' : ''} immediate attention.`,
      severity: 'critical',
    });
  }

  // SLA breaches
  const slaBreached = findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'BREACHED');
  if (slaBreached.length > 0) {
    insights.push({
      id: 'SLA_BREACH',
      message: `${slaBreached.length} open finding${slaBreached.length > 1 ? 's have' : ' has'} breached SLA. Escalation required.`,
      severity: 'critical',
    });
  }

  // Internet-facing critical assets
  const internetCritical = findings.filter(f => {
    const isFacing  = f.internet_exposure || f.detail?.asset_context?.internet_facing;
    const isCritical = (f.asset_criticality ?? '').toUpperCase() === 'CRITICAL';
    return isFacing && isCritical && (f.workflow?.status ?? '').toUpperCase() !== 'RESOLVED';
  });
  if (internetCritical.length > 0) {
    insights.push({
      id: 'INTERNET_CRITICAL',
      message: `${internetCritical.length} finding${internetCritical.length > 1 ? 's affect' : ' affects'} internet-facing critical assets.`,
      severity: 'warning',
    });
  }

  // KEV-listed findings
  const kevFindings = findings.filter(f => f.detail?.threat_intelligence?.kev_listed === true
    && (f.workflow?.status ?? '').toUpperCase() !== 'RESOLVED');
  if (kevFindings.length > 0) {
    insights.push({
      id: 'KEV_COUNT',
      message: `${kevFindings.length} finding${kevFindings.length > 1 ? 's are' : ' is'} listed in the CISA Known Exploited Vulnerabilities catalog.`,
      severity: 'critical',
    });
  }

  // SLA at-risk
  const slaAtRisk = findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'AT_RISK');
  if (slaAtRisk.length > 0) {
    insights.push({
      id: 'SLA_AT_RISK',
      message: `${slaAtRisk.length} finding${slaAtRisk.length > 1 ? 's are' : ' is'} approaching SLA deadlines.`,
      severity: 'warning',
    });
  }

  // Unassigned critical/high
  const unassigned = findings.filter(f => {
    const level = (f.risk_level ?? '').toUpperCase();
    return (level === 'CRITICAL' || level === 'HIGH')
      && !f.workflow?.assigned_to
      && (f.workflow?.status ?? '').toUpperCase() !== 'RESOLVED';
  });
  if (unassigned.length > 0) {
    insights.push({
      id: 'UNASSIGNED',
      message: `${unassigned.length} high-priority finding${unassigned.length > 1 ? 's have' : ' has'} no assigned owner.`,
      severity: 'warning',
    });
  }

  // High EPSS findings
  const highEpss = findings.filter(f =>
    (f.detail?.threat_intelligence?.epss_score ?? 0) >= 0.7
    && (f.workflow?.status ?? '').toUpperCase() !== 'RESOLVED'
  );
  if (highEpss.length > 0) {
    insights.push({
      id: 'HIGH_EPSS',
      message: `${highEpss.length} finding${highEpss.length > 1 ? 's have' : ' has'} EPSS ≥ 70% — elevated exploitation probability.`,
      severity: 'warning',
    });
  }

  return insights;
}

/**
 * aggregateDashboardStats — computes stats from findings for cross-checking
 * against dashboard_summary.json values.
 */
export function aggregateDashboardStats(findings) {
  if (!Array.isArray(findings)) return {};
  return {
    total: findings.length,
    critical: findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'CRITICAL').length,
    high:     findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'HIGH').length,
    medium:   findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'MEDIUM').length,
    low:      findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'LOW').length,
    open:     findings.filter(f => (f.workflow?.status ?? '').toUpperCase() === 'OPEN').length,
    resolved: findings.filter(f => (f.workflow?.status ?? '').toUpperCase() === 'RESOLVED').length,
    slaBreached: findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'BREACHED').length,
    slaAtRisk:   findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'AT_RISK').length,
    kevListed:   findings.filter(f => f.detail?.threat_intelligence?.kev_listed === true).length,
    internetFacing: findings.filter(f => f.internet_exposure || f.detail?.asset_context?.internet_facing).length,
  };
}
