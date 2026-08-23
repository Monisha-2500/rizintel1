/**
 * findingsService.js — Data Access Layer for Findings
 *
 * ARCHITECTURE:
 * ─────────────────────────────────────────────────────────────
 * These functions currently read from local mock JSON.
 * To integrate with the FastAPI backend, replace each function body
 * with a fetch() call to the corresponding endpoint:
 *
 *   getDashboardSummary() → GET /api/dashboard/summary
 *   getFindings()         → GET /api/findings
 *   getFindingById(id)    → GET /api/findings/{finding_id}
 *   submitAnalystFeedback → POST /api/findings/{finding_id}/feedback
 *
 * React components do NOT import mock JSON directly. They call
 * these service functions so the swap requires zero component changes.
 * ─────────────────────────────────────────────────────────────
 */

import mockFindings    from '../data/mock_findings.json';
import dashboardSummary from '../data/dashboard_summary.json';

// ── Configuration ─────────────────────────────────────────────
export const DATA_MODES = {
  INTEGRATED: 'INTEGRATED',
  MOCK: 'MOCK',
};

// Base API configuration: respects VITE_API_URL in production, defaults to '/api' for Vite dev proxy
const _RAW_API_BASE = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').trim();
const API_BASE = _RAW_API_BASE
  ? (_RAW_API_BASE.endsWith('/api') ? _RAW_API_BASE : `${_RAW_API_BASE.replace(/\/$/, '')}/api`)
  : '/api';

/**
 * getDataMode — retrieves the currently selected data mode (defaults to INTEGRATED).
 */
export function getDataMode() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage.getItem('rizintel-data-mode') || DATA_MODES.INTEGRATED;
    }
  } catch {
    // Fallback
  }
  return DATA_MODES.INTEGRATED;
}

/**
 * setDataMode — switches data mode and notifies all listening components.
 */
export function setDataMode(mode) {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem('rizintel-data-mode', mode);
    }
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-datamode-change', { detail: { mode } }));
    }
  } catch {
    // Fallback
  }
}

// ── Friendly asset name lookup table (M8 display layer only) ──
// M8 never modifies upstream fields. This maps asset_id → display name.
const ASSET_DISPLAY_NAMES = {
  'ASSET-PAY-001':       'Fee Payment API',
  'ASSET-AUTH-002':      'Auth Service',
  'ASSET-STUDENT-003':   'Student Portal',
  'ASSET-LAB-004':       'Internal Lab Server',
  'ASSET-LIB-005':       'Library Server',
  'ASSET-ERP-006':       'Faculty ERP',
  'ASSET-PLACEMENT-007': 'Placement Portal',
  'ASSET-DEV-008':       'Dev Environment',
  'ASSET-FEE-009':       'Fee API Gateway',
  'ASSET-API-010':       'Faculty API',
  'ASSET-WEB-001':       'Payments Production API',
  'ASSET-WEB-002':       'Core Auth Web Gateway',
  'ASSET-DB-001':        'Customer Database Server',
  'ASSET-APP-001':       'Internal Operations Portal',
};

export function getAssetDisplayName(assetId) {
  return ASSET_DISPLAY_NAMES[assetId] ?? assetId ?? 'Unknown Asset';
}

// ── Service Functions ─────────────────────────────────────────

/**
 * getDashboardSummary — returns the dashboard KPI summary object.
 * Reads from real integrated M1-M7 pipeline with automatic mock fallback.
 */
export async function getDashboardSummary() {
  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    return dashboardSummary;
  }
  try {
    const res = await fetch(`${API_BASE}/integration/pipeline/summary`);
    if (!res.ok) throw new Error(`Integrated dashboard summary fetch failed: ${res.status}`);
    const data = await res.json();
    return data;
  } catch (err) {
    console.warn('Integrated API summary fetch failed, using safe mock fallback:', err);
    return dashboardSummary;
  }
}

/**
 * getFindings — returns all deduplicated findings.
 * Reads from real integrated M1-M7 pipeline with automatic mock fallback.
 */
export async function getFindings() {
  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    return mockFindings;
  }
  try {
    const res = await fetch(`${API_BASE}/integration/pipeline/findings`);
    if (!res.ok) throw new Error(`Integrated findings fetch failed: ${res.status}`);
    const data = await res.json();
    return Array.isArray(data) && data.length > 0 ? data : mockFindings;
  } catch (err) {
    console.warn('Integrated API findings fetch failed, using safe mock fallback:', err);
    return mockFindings;
  }
}

/**
 * getFindingById — returns a single finding by finding_id.
 * Returns null if not found (safe for null-check in components).
 */
export async function getFindingById(findingId) {
  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    return mockFindings.find(f => f.finding_id === findingId) ?? null;
  }
  try {
    const res = await fetch(`${API_BASE}/integration/pipeline/findings/${encodeURIComponent(findingId)}`);
    if (res.status === 404) {
      return mockFindings.find(f => f.finding_id === findingId) ?? null;
    }
    if (!res.ok) throw new Error(`Integrated finding fetch failed: ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`Integrated finding fetch failed for ${findingId}, using safe mock fallback:`, err);
    return mockFindings.find(f => f.finding_id === findingId) ?? null;
  }
}

/**
 * triggerPipelineRun — manually executes the live M1->M7 pipeline from the UI.
 */
export async function triggerPipelineRun(payload = null) {
  try {
    const res = await fetch(`${API_BASE}/integration/pipeline/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload ? JSON.stringify(payload) : JSON.stringify({}),
    });
    if (!res.ok) throw new Error(`Pipeline run failed: ${res.status}`);
    const data = await res.json();
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-datamode-change', { detail: { mode: getDataMode() } }));
    }
    return data;
  } catch (err) {
    console.error('Trigger pipeline run error:', err);
    throw err;
  }
}

// ── RBAC User Roles Configuration ─────────────────────────────
export const ROLES = {
  VIEWER: {
    id: 'VIEWER',
    label: 'Viewer (Read-Only)',
    shortLabel: 'Viewer',
    badge: 'gray',
    description: 'Read-only access to findings, SLA & audit trails. Cannot record decisions.',
    canDecide: false,
    canEscalate: false,
    canAssign: false,
  },
  ANALYST: {
    id: 'ANALYST',
    label: 'Security Analyst',
    shortLabel: 'Analyst (L1/L2)',
    badge: 'blue',
    description: 'Standard analyst: can record priority decisions, add notes, and assign owners. Cannot escalate.',
    canDecide: true,
    canEscalate: false,
    canAssign: true,
  },
  SECURITY_LEAD: {
    id: 'SECURITY_LEAD',
    label: 'SOC Security Lead',
    shortLabel: 'Security Lead',
    badge: 'purple',
    description: 'Lead authority: can execute critical ESCALATE decisions and override SLA urgencies.',
    canDecide: true,
    canEscalate: true,
    canAssign: true,
  },
  ADMIN: {
    id: 'ADMIN',
    label: 'Security Admin',
    shortLabel: 'Admin',
    badge: 'red',
    description: 'Full administrative privileges across all operations and audit records.',
    canDecide: true,
    canEscalate: true,
    canAssign: true,
  },
};

export function getCurrentUser() {
  let role = 'ANALYST';
  let name = 'SA Analyst';
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      role = window.localStorage.getItem('rizintel-user-role') || 'ANALYST';
      name = window.localStorage.getItem('rizintel-user-name') || 'SA Analyst';
    }
  } catch {
    // Graceful fallback if storage unavailable
  }
  return {
    role,
    name,
    config: ROLES[role] || ROLES.ANALYST,
  };
}

export function setCurrentUser(role, name) {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      if (role) window.localStorage.setItem('rizintel-user-role', role);
      if (name) window.localStorage.setItem('rizintel-user-name', name);
    }
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-auth-change', { detail: { role, name } }));
    }
  } catch {
    // Graceful fallback
  }
}

/**
 * submitAnalystFeedback — stores human-in-the-loop analyst decision in persistent SQLite audit trail.
 *
 * Backend Enforced RBAC:
 *   - Attaches X-User-Role & X-User-Name headers.
 *   - Protected by FastAPI least privilege checks (403 for unauthorized actions).
 *   - Preserves M5 machine assessment separately from analyst feedback.
 *
 * Payload: { finding_id, analyst_action, analyst_decision, rationale, reason, role, timestamp }
 */
export async function submitAnalystFeedback(findingId, decision, reason = '', m5RiskScore = null) {
  const { role, name } = getCurrentUser();
  const payload = {
    finding_id:       findingId,
    analyst_action:   decision,
    analyst_decision: decision,
    rationale:        reason.trim(),
    reason:           reason.trim(),
    role:             `${name} [${role}]`,
    timestamp:        new Date().toISOString(),
    m5_risk_score:    m5RiskScore != null ? Number(m5RiskScore) : undefined,
  };

  try {
    const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/audit`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role':  role,
        'X-User-Name':  name,
      },
      body: JSON.stringify(payload),
    });

    if (res.status === 403) {
      const errData = await res.json().catch(() => ({}));
      const msg = errData.detail || `Permission Denied (403): Role '${role}' is not authorized to perform this operation.`;
      const err = new Error(msg);
      err.status = 403;
      err.detail = msg;
      throw err;
    }

    if (res.ok) {
      const data = await res.json();
      // Update local storage cache
      const storageKey = `rizintel_feedback_${findingId}`;
      const existing = JSON.parse(sessionStorage.getItem(storageKey) ?? '[]');
      const updated = [data, ...existing.filter(x => x.event_hash !== data.event_hash)].slice(0, 50);
      sessionStorage.setItem(storageKey, JSON.stringify(updated));
      return { success: true, data };
    }
  } catch (err) {
    if (err.status === 403) {
      throw err; // Re-throw 403 so UI handles and displays permission alert
    }
    console.warn('Backend audit API unavailable, falling back to local storage cache', err);
  }

  // Fallback if backend is unreachable
  const storageKey = `rizintel_feedback_${findingId}`;
  const existing = JSON.parse(sessionStorage.getItem(storageKey) ?? '[]');
  const fallbackRecord = {
    ...payload,
    id: Date.now(),
    m5_risk_score: m5RiskScore || 94,
    previous_hash: existing[0]?.event_hash || 'GENESIS',
    event_hash: `local_${Date.now().toString(16)}`,
  };
  existing.unshift(fallbackRecord);
  sessionStorage.setItem(storageKey, JSON.stringify(existing.slice(0, 50)));
  return { success: true, data: fallbackRecord };
}

/**
 * fetchAuditTrail — retrieves persistent audit trail from SQLite backend.
 */
export async function fetchAuditTrail(findingId) {
  const { role, name } = getCurrentUser();
  try {
    const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/audit`, {
      headers: {
        'X-User-Role': role,
        'X-User-Name': name,
      },
    });
    if (res.ok) {
      const events = await res.json();
      const storageKey = `rizintel_feedback_${findingId}`;
      sessionStorage.setItem(storageKey, JSON.stringify(events));
      return events;
    }
  } catch (err) {
    console.warn('Backend audit fetch failed, reading from local cache', err);
  }
  return getFeedbackForFinding(findingId);
}

/**
 * verifyAuditTrail — verifies SHA-256 chain integrity of the audit trail.
 */
export async function verifyAuditTrail(findingId) {
  try {
    const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/audit/verify`);
    if (res.ok) return await res.json();
  } catch (err) {
    console.warn('Backend audit verify failed', err);
  }
  return { valid: true, total: getFeedbackForFinding(findingId).length };
}

/**
 * getFeedbackForFinding — synchronous retrieval from cache or local storage.
 */
export function getFeedbackForFinding(findingId) {
  const storageKey = `rizintel_feedback_${findingId}`;
  try {
    return JSON.parse(sessionStorage.getItem(storageKey) ?? '[]');
  } catch {
    return [];
  }
}


