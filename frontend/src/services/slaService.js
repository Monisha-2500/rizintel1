/**
 * slaService.js — SLA Data & Remediation Task Service.
 * Provides tenant-scoped, authoritative SLA metrics and task associations.
 */

import { fetchWithAuth, getAssetDisplayName, getFindings } from './findingsService';

export const TEAM_DISPLAY_MAP = {
  'secops': 'SOC Operations Team',
  'appsec-team': 'Application Security Team',
  'payments-infra': 'Payments Engineering',
  'payments': 'Payments Engineering',
  'dev-lead': 'Lead Developer',
  'cloud-eng': 'Cloud Infrastructure',
  'infra': 'Infrastructure Team',
  'webteam': 'Web Applications Team',
  'erpteam': 'Enterprise Applications Team',
  'unassigned': 'Unassigned Queue',
};

export function getTeamDisplayName(handleOrId) {
  if (!handleOrId || handleOrId === '—' || String(handleOrId).toLowerCase().trim() === 'unassigned') return 'Unassigned';
  const key = String(handleOrId).toLowerCase().trim();
  return TEAM_DISPLAY_MAP[key] || handleOrId;
}

/**
 * Fetch server-authoritative categorized SLA findings.
 */
export async function getSLAItems(params = {}) {
  try {
    const query = new URLSearchParams(params).toString();
    const url = `/api/sla${query ? `?${query}` : ''}`;
    const res = await fetchWithAuth(url);
    if (res.ok) {
      const data = await res.json();
      if (data && (data.BREACHED || data.AT_RISK || data.ON_TRACK || data.MET)) {
        return data;
      }
    }
  } catch (err) {
    console.warn('API /api/sla request failed, falling back to findings compilation:', err);
  }

  // Fallback to findings compilation
  try {
    const findings = await getFindings(params);
    return deriveSLAItemsFromFindings(findings);
  } catch (err) {
    console.error('Failed to retrieve SLA items:', err);
    return { BREACHED: [], AT_RISK: [], ON_TRACK: [], MET: [] };
  }
}

/**
 * Fetch active breach warnings from monitoring sweep.
 */
export async function getBreachWarnings() {
  try {
    const res = await fetchWithAuth('/api/remediation/monitor/breach-warnings');
    if (res.ok) return await res.json();
  } catch (err) {
    try {
      const alt = await fetchWithAuth('/api/sla/breach-warnings');
      if (alt.ok) return await alt.json();
    } catch {
      // return default
    }
  }
  return { hard_breaches: [], predictive_warnings: [] };
}

/**
 * Fetch persisted remediation tasks list.
 */
export async function getRemediationTasks(params = {}) {
  try {
    const query = new URLSearchParams(params).toString();
    const url = `/api/remediation/tasks${query ? `?${query}` : ''}`;
    const res = await fetchWithAuth(url);
    if (res.ok) {
      const tasks = await res.json();
      return Array.isArray(tasks) ? tasks : [];
    }
    return [];
  } catch (err) {
    console.warn('Failed to retrieve remediation tasks:', err);
    return [];
  }
}

/**
 * Fetch aggregate remediation stats for organization.
 */
export async function getRemediationSummary(params = {}) {
  try {
    const query = new URLSearchParams(params).toString();
    const url = `/api/remediation/stats/summary${query ? `?${query}` : ''}`;
    const res = await fetchWithAuth(url);
    if (res.ok) return await res.json();
  } catch (err) {
    console.warn('Failed to retrieve remediation summary:', err);
  }
  return { total: 0, by_status: {}, by_priority: {} };
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
      asset_display:     f.detail?.asset_context?.asset_name || getAssetDisplayName(f.asset_id) || f.asset_id,
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
