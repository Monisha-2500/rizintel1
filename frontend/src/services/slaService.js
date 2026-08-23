/**
 * slaService.js — SLA data service.
 * Derives SLA groupings from findings.
 * Replace with GET /api/sla for live integration.
 */

import mockFindings from '../data/mock_findings.json';
import { getAssetDisplayName, getFindings } from './findingsService';

export async function getSLAItems() {
  try {
    const findings = await getFindings();
    return deriveSLAItemsFromFindings(findings);
  } catch (err) {
    console.warn('Failed to retrieve findings for SLA view, using mock fallback:', err);
    return deriveSLAItemsFromFindings(mockFindings);
  }
}

/**
 * deriveSLAItemsFromFindings — maps findings to SLA display objects.
 * Groups are computed from sla_status field (M7 output — M8 only reads it).
 * Pure function.
 */
export function deriveSLAItemsFromFindings(findings) {
  if (!Array.isArray(findings)) return { BREACHED: [], AT_RISK: [], ON_TRACK: [], MET: [] };

  const groups = { BREACHED: [], AT_RISK: [], ON_TRACK: [], MET: [] };

  findings.forEach(f => {
    const slaStatus = (f.workflow?.sla_status ?? 'ON_TRACK').toUpperCase();
    const item = {
      finding_id:        f.finding_id,
      vulnerability_name: f.vulnerability_name,
      risk_score:        f.risk_score,
      risk_level:        f.risk_level,
      asset_display:     getAssetDisplayName(f.asset_id),
      asset_id:          f.asset_id,
      ticket_id:         f.workflow?.ticket_id ?? 'N/A',
      owner:             f.workflow?.assigned_to ?? '—',
      sla_due_at:        f.workflow?.sla_due_at ?? null,
      sla_status:        slaStatus,
      escalation_level:  f.workflow?.escalation_level ?? 0,
      workflow_status:   f.workflow?.status ?? 'OPEN',
    };

    if (groups[slaStatus]) {
      groups[slaStatus].push(item);
    } else {
      groups['ON_TRACK'].push(item);
    }
  });

  // Sort each group by risk score descending
  Object.keys(groups).forEach(key => {
    groups[key].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
  });

  return groups;
}
