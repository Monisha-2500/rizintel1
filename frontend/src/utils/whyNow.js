/**
 * whyNow.js — Deterministic "Why Now?" Reason Engine
 *
 * Generates evidence-backed reasons explaining why a vulnerability
 * requires attention NOW. Each reason is only emitted when supported
 * by actual JSON data — never fabricated.
 *
 * M8 does NOT recalculate risk scores. These reasons visualise the
 * existing M5 score factors for the analyst.
 */

/** EPSS threshold above which "high exploitation probability" is emitted */
const EPSS_HIGH_THRESHOLD = 0.7;

/** Scanner consensus threshold for "confirmed by multiple scanners" */
const CONSENSUS_HIGH_THRESHOLD = 0.67;

/**
 * generateWhyNowReasons(finding) → [{ id, icon, label, evidence, severity }]
 *
 * severity: 'critical' | 'warning' | 'info'
 */
export function generateWhyNowReasons(finding) {
  if (!finding) return [];

  const reasons = [];
  const ti  = finding.detail?.threat_intelligence  ?? {};
  const ac  = finding.detail?.asset_context         ?? {};
  const sc  = finding.detail?.scanner_consensus     ?? {};
  const fc  = finding.detail?.finding_confidence    ?? {};
  const wf  = finding.workflow                       ?? {};

  // 1. CISA KEV listed
  if (ti.kev_listed === true) {
    reasons.push({
      id:       'KEV',
      icon:     '🚨',
      label:    'Known Exploited Vulnerability',
      evidence: 'Listed in CISA Known Exploited Vulnerabilities Catalog.',
      severity: 'critical',
    });
  }

  // 2. High EPSS score
  if (typeof ti.epss_score === 'number' && ti.epss_score >= EPSS_HIGH_THRESHOLD) {
    reasons.push({
      id:       'EPSS',
      icon:     '📈',
      label:    'High Exploitation Probability',
      evidence: `EPSS score ${(ti.epss_score * 100).toFixed(0)}% — high likelihood of exploitation in the wild.`,
      severity: 'critical',
    });
  }

  // 3. Public exploit available
  if (ti.exploit_available === true) {
    reasons.push({
      id:       'EXPLOIT',
      icon:     '💥',
      label:    'Public Exploit Available',
      evidence: 'A functional exploit is publicly available for this vulnerability.',
      severity: 'critical',
    });
  }

  // 4. Critical asset
  const criticality = (ac.criticality ?? finding.asset_criticality ?? '').toUpperCase();
  if (criticality === 'CRITICAL') {
    reasons.push({
      id:       'CRITICAL_ASSET',
      icon:     '🏛️',
      label:    'Critical Organizational Asset',
      evidence: `Asset classified as CRITICAL (${ac.data_sensitivity ?? 'sensitive data'}).`,
      severity: 'warning',
    });
  }

  // 5. Internet-facing
  const isFacing = ac.internet_facing ?? finding.internet_exposure ?? false;
  if (isFacing === true) {
    reasons.push({
      id:       'INTERNET',
      icon:     '🌐',
      label:    'Internet-Facing Asset',
      evidence: 'The affected asset is directly accessible from the internet.',
      severity: 'warning',
    });
  }

  // 6. High scanner consensus
  if (typeof sc.score === 'number' && sc.score >= CONSENSUS_HIGH_THRESHOLD) {
    const scanners = (sc.scanner_names ?? []).join(', ');
    reasons.push({
      id:       'SCANNER_CONSENSUS',
      icon:     '🔍',
      label:    'Confirmed by Multiple Scanners',
      evidence: `Detected by ${sc.detected_by_count ?? '?'} of ${sc.total_scanners ?? '?'} scanners: ${scanners || 'N/A'}.`,
      severity: 'info',
    });
  }

  // 7. SLA already breached
  if ((wf.sla_status ?? '').toUpperCase() === 'BREACHED') {
    reasons.push({
      id:       'SLA_BREACHED',
      icon:     '⏰',
      label:    'SLA Already Breached',
      evidence: `Remediation deadline was ${wf.sla_due_at ? new Date(wf.sla_due_at).toLocaleDateString() : 'unknown'}. Immediate escalation required.`,
      severity: 'critical',
    });
  }

  // 8. SLA at risk
  if ((wf.sla_status ?? '').toUpperCase() === 'AT_RISK') {
    reasons.push({
      id:       'SLA_AT_RISK',
      icon:     '⚠️',
      label:    'SLA Deadline Approaching',
      evidence: `Remediation SLA is at risk. Due: ${wf.sla_due_at ? new Date(wf.sla_due_at).toLocaleString() : 'N/A'}.`,
      severity: 'warning',
    });
  }

  return reasons;
}

/**
 * hasUrgentReasons — quick boolean check for indicator display.
 */
export function hasUrgentReasons(finding) {
  const reasons = generateWhyNowReasons(finding);
  return reasons.some(r => r.severity === 'critical');
}
