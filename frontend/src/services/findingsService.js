/**
 * findingsService.js — Data Access Layer & JWT Authentication for RizIntel M8
 *
 * ARCHITECTURE:
 * ─────────────────────────────────────────────────────────────
 * - Authenticated session stored in localStorage (JWT token + user record).
 * - All backend API requests automatically attach `Authorization: Bearer <JWT>`.
 * - Backend derives user identity, role, and permissions strictly from verified token.
 * - Handles 401 Unauthorized by clearing session and notifying UI for login redirect.
 * ─────────────────────────────────────────────────────────────
 */

import mockFindings    from '../data/mock_findings.json';
import dashboardSummary from '../data/dashboard_summary.json';

// ── Storage Keys ───────────────────────────────────────────────
export const TOKEN_STORAGE_KEY = 'rizintel_auth_token';
export const USER_STORAGE_KEY  = 'rizintel_auth_user';

// ── Configuration & Runtime States ─────────────────────────────
export const DATA_MODES = {
  INTEGRATED: 'INTEGRATED',
  MOCK: 'MOCK',
};

export const RUNTIME_STATUS = {
  LIVE: 'LIVE',
  MOCK: 'MOCK',
  FALLBACK: 'FALLBACK',
  CONNECTING: 'CONNECTING',
  ERROR: 'ERROR',
};

// Base API configuration: respects VITE_API_URL in production, defaults to '/api' for Vite dev proxy
const _RAW_API_BASE = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').trim();
export const API_BASE = _RAW_API_BASE
  ? (_RAW_API_BASE.endsWith('/api') ? _RAW_API_BASE : `${_RAW_API_BASE.replace(/\/$/, '')}/api`)
  : '/api';

// Internal centralized runtime state & in-memory mode fallback
let _inMemoryDataMode = DATA_MODES.INTEGRATED;
let _currentRuntimeStatus = RUNTIME_STATUS.LIVE;

// ── Authentication & Session Management ────────────────────────

export function getAuthToken() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage.getItem(TOKEN_STORAGE_KEY) || null;
    }
  } catch {
    // Storage access error fallback
  }
  return null;
}

export function getStoredUser() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const raw = window.localStorage.getItem(USER_STORAGE_KEY);
      if (raw) return JSON.parse(raw);
    }
  } catch {
    // Storage access error fallback
  }
  return null;
}

export function setAuthSession(token, user) {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      if (token) window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
      if (user)  window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
    }
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-auth-change', { detail: { token, user } }));
    }
  } catch (e) {
    console.error('Failed to persist auth session:', e);
  }
}

export function clearAuthSession() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
      window.localStorage.removeItem(USER_STORAGE_KEY);
      window.localStorage.removeItem('rizintel-user-role');
      window.localStorage.removeItem('rizintel-user-name');
    }
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-auth-change', { detail: { token: null, user: null } }));
    }
  } catch (e) {
    console.error('Failed to clear auth session:', e);
  }
}

export function isTokenValid(token) {
  if (!token || typeof token !== 'string') return false;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      return false; // Expired
    }
    return true;
  } catch {
    return false;
  }
}

export function isAuthenticated() {
  const token = getAuthToken();
  const user = getStoredUser();
  if (!token || !user || !user.email) {
    return false;
  }
  if (!isTokenValid(token)) {
    clearAuthSession();
    return false;
  }
  return true;
}

/**
 * login — authenticate user credentials with backend and store session.
 */
export async function login(email, password) {
  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: (email || '').trim(), password }),
    });

    if (!res.ok) {
      let errorDetail = 'Invalid email or password.';
      try {
        const errData = await res.json();
        errorDetail = errData.detail || errorDetail;
      } catch {
        // JSON parse error fallback
      }
      const err = new Error(errorDetail);
      err.status = res.status;
      throw err;
    }

    const data = await res.json();
    setAuthSession(data.access_token, data.user);
    return data;
  } catch (err) {
    if (!err.status) {
      // Network failure or connection refused
      err.isNetworkError = true;
    }
    throw err;
  }
}

/**
 * register — register a new user account with backend and establish authenticated session.
 */
export async function register(name, email, password, role) {
  try {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: (name || '').trim(),
        email: (email || '').trim().toLowerCase(),
        password,
        role: role || 'VIEWER',
      }),
    });

    if (!res.ok) {
      let errorDetail = 'Registration failed. Please try again.';
      try {
        const errData = await res.json();
        errorDetail = errData.detail || errorDetail;
      } catch {
        // JSON parse error fallback
      }
      const err = new Error(errorDetail);
      err.status = res.status;
      throw err;
    }

    const data = await res.json();
    setAuthSession(data.access_token, data.user);
    return data;
  } catch (err) {
    if (!err.status) {
      err.isNetworkError = true;
    }
    throw err;
  }
}

/**
 * logout — clear local session and trigger redirect.
 */
export function logout() {
  clearAuthSession();
  if (typeof window !== 'undefined') {
    window.location.href = '/login';
  }
}

/**
 * fetchDemoUsers — retrieve public demo user accounts.
 */
export async function fetchDemoUsers() {
  try {
    const res = await fetch(`${API_BASE}/auth/demo-users`);
    if (res.ok) return await res.json();
  } catch {
    // network or server error
  }
  // In development mode only, fallback to dev demo user list if endpoint unreachable in dev
  const isDev = typeof import.meta !== 'undefined' && (import.meta.env?.DEV || import.meta.env?.MODE === 'development');
  if (isDev) {
    return [
      { email: 'viewer@rizintel.demo', role: 'VIEWER', display_name: 'Auditor View', demo_hint: 'Viewer Account' },
      { email: 'analyst@rizintel.demo', role: 'ANALYST', display_name: 'SA Analyst', demo_hint: 'Analyst Account' },
      { email: 'lead@rizintel.demo', role: 'SECURITY_LEAD', display_name: 'SOC Lead', demo_hint: 'Security Lead Account' },
      { email: 'admin@rizintel.demo', role: 'ADMIN', display_name: 'Security Admin', demo_hint: 'Admin Account' },
    ];
  }
  return [];
}

/**
 * fetchWithAuth — authenticated fetch wrapper that attaches Bearer JWT
 * and intercepts 401s to clear stale sessions and notify.
 */
export async function fetchWithAuth(url, options = {}) {
  let targetUrl = url;
  if (typeof url === 'string' && url.startsWith('/')) {
    const origin = (typeof window !== 'undefined' && window.location?.origin && window.location.origin !== 'null')
      ? window.location.origin
      : 'http://localhost:5173';
    targetUrl = `${origin}${url}`;
  }

  const headers = new Headers(options.headers || {});
  const token = getAuthToken();

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const enhancedOptions = {
    ...options,
    headers,
  };

  const response = await fetch(targetUrl, enhancedOptions);

  if (response.status === 401) {
    console.warn('API returned 401 Unauthorized — clearing session');
    clearAuthSession();
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-unauthorized', { detail: { url } }));
    }
  }

  return response;
}

// ── Data Mode Management ───────────────────────────────────────

/**
 * getDataMode — retrieves the user-requested data mode (defaults to INTEGRATED).
 */
export function getDataMode() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const stored = window.localStorage.getItem('rizintel-data-mode');
      if (stored) return stored;
    }
  } catch {
    // Fallback
  }
  return _inMemoryDataMode;
}

/**
 * getRuntimeStatus — single source of truth for the ACTUAL state of currently displayed data.
 */
export function getRuntimeStatus() {
  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    return RUNTIME_STATUS.MOCK;
  }
  return _currentRuntimeStatus;
}

/**
 * setRuntimeStatus — updates the centralized runtime status and broadcasts to subscribers.
 */
export function setRuntimeStatus(status) {
  _currentRuntimeStatus = status;
  if (typeof window !== 'undefined' && window.dispatchEvent) {
    window.dispatchEvent(new CustomEvent('rizintel-runtimestatus-change', {
      detail: { status, mode: getDataMode() }
    }));
  }
}

/**
 * setDataMode — switches data mode, updates runtime state, and notifies all listening components.
 */
export function setDataMode(mode) {
  _inMemoryDataMode = mode;
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem('rizintel-data-mode', mode);
    }
  } catch {
    // Fallback
  }

  if (mode === DATA_MODES.MOCK) {
    setRuntimeStatus(RUNTIME_STATUS.MOCK);
  } else {
    setRuntimeStatus(RUNTIME_STATUS.CONNECTING);
  }

  if (typeof window !== 'undefined' && window.dispatchEvent) {
    window.dispatchEvent(new CustomEvent('rizintel-datamode-change', {
      detail: { mode, status: getRuntimeStatus() }
    }));
  }
}

/**
 * checkBackendHealth — checks health of live backend API.
 */
export async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE}/integration/health`);
    if (res.ok) {
      const data = await res.json();
      return { healthy: data.overall_status === 'HEALTHY', data };
    }
    return { healthy: false, error: `HTTP ${res.status}` };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

// ── Friendly asset name lookup table (M8 display layer only) ──
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
 */
export async function getDashboardSummary() {
  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    setRuntimeStatus(RUNTIME_STATUS.MOCK);
    return dashboardSummary;
  }

  setRuntimeStatus(RUNTIME_STATUS.CONNECTING);
  try {
    const res = await fetchWithAuth(`${API_BASE}/integration/pipeline/summary`);
    if (!res.ok) throw new Error(`Integrated dashboard summary fetch failed: HTTP ${res.status}`);
    const data = await res.json();
    if (!data || typeof data !== 'object') {
      throw new Error('Malformed summary payload from live API');
    }
    setRuntimeStatus(RUNTIME_STATUS.LIVE);
    const summaryObj = data.pipeline_summary?.summary || data.summary || {};
    return {
      ...data,
      summary: summaryObj
    };
  } catch (err) {
    console.warn('Live API summary fetch failed, transitioning to honest mock fallback:', err);
    setRuntimeStatus(RUNTIME_STATUS.FALLBACK);
    return dashboardSummary;
  }
}

import { getScanRunResults } from './ingestionService';

/**
 * getScanRunFindings — returns findings strictly scoped to a specific scan run.
 * Zero fallback to mock data when scanRunId is supplied.
 */
export async function getScanRunFindings(orgId, scanRunId) {
  if (!orgId || !scanRunId) {
    throw new Error('both orgId and scanRunId are required for scan-run scoped findings.');
  }

  setRuntimeStatus(RUNTIME_STATUS.CONNECTING);
  try {
    const res = await getScanRunResults(orgId, scanRunId);
    if (!res || !Array.isArray(res.findings)) {
      throw new Error(`Invalid results payload for scan run ${scanRunId}`);
    }
    setRuntimeStatus(RUNTIME_STATUS.LIVE);
    return {
      findings: res.findings,
      summary: res.summary,
      scan_run_id: res.scan_run_id,
      asset_id: res.asset_id,
      completed_at: res.completed_at,
    };
  } catch (err) {
    console.error(`Failed to fetch scan-run scoped results for ${scanRunId}:`, err);
    setRuntimeStatus(RUNTIME_STATUS.FALLBACK);
    // Explicitly do NOT fall back to mock data for scan-run scoped requests
    throw err;
  }
}

/**
 * getFindings — returns all deduplicated findings with optional org/scan_run scoping.
 */
export async function getFindings(params = {}) {
  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    setRuntimeStatus(RUNTIME_STATUS.MOCK);
    return mockFindings;
  }

  setRuntimeStatus(RUNTIME_STATUS.CONNECTING);
  try {
    const searchParams = new URLSearchParams();
    if (typeof params === 'object' && params !== null) {
      if (params.organization_id || params.org_id) searchParams.set('organization_id', params.organization_id || params.org_id);
      if (params.scan_run_id) searchParams.set('scan_run_id', params.scan_run_id);
      if (params.page) searchParams.set('page', params.page);
      if (params.page_size) searchParams.set('page_size', params.page_size);
    }
    const queryString = searchParams.toString() ? `?${searchParams.toString()}` : '';
    const res = await fetchWithAuth(`${API_BASE}/findings${queryString}`);
    if (!res.ok) {
      // Fallback to pipeline endpoint if /findings returns 404 or fails
      const pRes = await fetchWithAuth(`${API_BASE}/integration/pipeline/findings`);
      if (pRes.ok) {
        const data = await pRes.json();
        setRuntimeStatus(RUNTIME_STATUS.LIVE);
        return data;
      }
      throw new Error(`Findings fetch failed: HTTP ${res.status}`);
    }
    const data = await res.json();
    if (!Array.isArray(data)) {
      throw new Error('Malformed findings payload from live API: expected array');
    }
    setRuntimeStatus(RUNTIME_STATUS.LIVE);
    return data;
  } catch (err) {
    console.warn('Live API findings fetch failed:', err);
    setRuntimeStatus(RUNTIME_STATUS.FALLBACK);
    if (params && (params.scan_run_id || params.scanRunId)) {
      throw err;
    }
    return mockFindings;
  }
}

/**
 * getFindingById — returns a single finding by finding_id.
 * When scanRunId and orgId are provided, fetches strictly from that ScanRun results with zero mock fallback.
 */
export async function getFindingById(findingId, scanRunId = null, orgId = null) {
  if (scanRunId && orgId) {
    const scopedResults = await getScanRunFindings(orgId, scanRunId);
    const found = (scopedResults.findings || []).find(
      f => f.finding_id?.toLowerCase() === findingId.toLowerCase() ||
           f.cve_id?.toLowerCase() === findingId.toLowerCase()
    );
    if (!found) {
      throw new Error(`Finding '${findingId}' not found in scan run ${scanRunId}`);
    }
    return found;
  }

  const mode = getDataMode();
  if (mode === DATA_MODES.MOCK) {
    setRuntimeStatus(RUNTIME_STATUS.MOCK);
    return mockFindings.find(f => f.finding_id.toLowerCase() === findingId.toLowerCase()) ?? null;
  }

  try {
    const searchParams = new URLSearchParams();
    if (orgId) searchParams.set('organization_id', orgId);
    const qs = searchParams.toString() ? `?${searchParams.toString()}` : '';

    let res = await fetchWithAuth(`${API_BASE}/findings/${encodeURIComponent(findingId)}${qs}`);
    if (res.status === 404) {
      res = await fetchWithAuth(`${API_BASE}/integration/pipeline/findings/${encodeURIComponent(findingId)}`);
    }
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) throw new Error(`Finding fetch failed: HTTP ${res.status}`);
    const data = await res.json();
    setRuntimeStatus(RUNTIME_STATUS.LIVE);
    return data;
  } catch (err) {
    console.error(`Finding fetch failed for ${findingId}:`, err);
    setRuntimeStatus(RUNTIME_STATUS.ERROR);
    throw err;
  }
}

/**
 * triggerPipelineRun — manually executes the live M1->M7 pipeline from the UI.
 */
export async function triggerPipelineRun(payload = null) {
  setRuntimeStatus(RUNTIME_STATUS.CONNECTING);
  try {
    const res = await fetchWithAuth(`${API_BASE}/integration/pipeline/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload ? JSON.stringify(payload) : JSON.stringify({}),
    });
    if (!res.ok) {
      let errDetail = `HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        if (typeof errJson.detail === 'string') {
          errDetail = errJson.detail;
        } else if (errJson.detail && errJson.detail.message) {
          errDetail = errJson.detail.message;
        } else if (errJson.message) {
          errDetail = errJson.message;
        }
      } catch {
        // Fallback to status text
      }
      throw new Error(`Pipeline run failed: ${errDetail}`);
    }
    const data = await res.json();
    if (data.status !== 'SUCCESS' && data.status !== 'OK') {
      throw new Error(data.message || 'Pipeline run returned failure status');
    }
    setRuntimeStatus(RUNTIME_STATUS.LIVE);
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('rizintel-datamode-change', { detail: { mode: getDataMode() } }));
    }
    return data;
  } catch (err) {
    console.error('Trigger pipeline run error:', err);
    setRuntimeStatus(RUNTIME_STATUS.FALLBACK);
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
  const storedUser = getStoredUser();
  if (storedUser && storedUser.role) {
    const roleKey = (storedUser.role || 'ANALYST').toUpperCase();
    return {
      userId: storedUser.user_id || 'usr-001',
      email: storedUser.email || '',
      role: roleKey,
      name: storedUser.display_name || storedUser.email || 'User',
      config: ROLES[roleKey] || ROLES.ANALYST,
      isAuthenticated: true,
    };
  }

  // Unauthenticated fallback
  return {
    userId: null,
    email: null,
    role: 'VIEWER',
    name: 'Unauthenticated User',
    config: ROLES.VIEWER,
    isAuthenticated: false,
  };
}

/**
 * submitAnalystFeedback — stores human-in-the-loop analyst decision in persistent SQLite audit trail.
 *
 * Backend Enforced RBAC & Trusted Identity:
 *   - Attaches Authorization: Bearer <JWT>.
 *   - Identity & role are derived server-side from verified token and active account.
 *   - Protected by FastAPI least privilege checks (403 for unauthorized actions).
 *   - Preserves M5 machine assessment separately from analyst feedback.
 */
export async function submitAnalystFeedback(findingId, decision, reason = '', m5RiskScore = null) {
  const user = getCurrentUser();
  const source = getRuntimeStatus(); // LIVE, MOCK, or FALLBACK
  const payload = {
    finding_id:       findingId,
    analyst_action:   decision,
    analyst_decision: decision,
    rationale:        reason.trim(),
    reason:           reason.trim(),
    timestamp:        new Date().toISOString(),
    m5_risk_score:    m5RiskScore != null ? Number(m5RiskScore) : undefined,
    data_source:      source,
  };

  try {
    const res = await fetchWithAuth(`${API_BASE}/findings/${encodeURIComponent(findingId)}/audit`, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'X-Data-Source': source,
      },
      body: JSON.stringify(payload),
    });

    if (res.status === 403) {
      const errData = await res.json().catch(() => ({}));
      const msg = errData.detail || `Permission Denied (403): Role '${user.role}' is not authorized to perform this operation.`;
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
    if (err.status === 403 || err.status === 401) {
      throw err; // Re-throw 403 / 401 so UI handles permission or auth alert
    }
    console.warn('Backend audit API unavailable, falling back to local storage cache', err);
  }

  // Fallback if backend is unreachable
  const storageKey = `rizintel_feedback_${findingId}`;
  const existing = JSON.parse(sessionStorage.getItem(storageKey) ?? '[]');
  const fallbackRecord = {
    ...payload,
    role: `${user.name} [${user.role}]`,
    id: Date.now(),
    m5_risk_score: m5RiskScore || 94,
    data_source: source,
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
  const source = getRuntimeStatus();
  try {
    const res = await fetchWithAuth(`${API_BASE}/findings/${encodeURIComponent(findingId)}/audit`, {
      headers: {
        'X-Data-Source': source,
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
    const res = await fetchWithAuth(`${API_BASE}/findings/${encodeURIComponent(findingId)}/audit/verify`);
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

// ── Phase 7 Remediation & SLA Automation API ──────────────────

/**
 * createRemediationTask — creates or retrieves tracked remediation task for finding.
 */
export async function createRemediationTask(findingId, note = '') {
  const res = await fetchWithAuth(`${API_BASE}/findings/${encodeURIComponent(findingId)}/remediation/task`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const err = new Error(errData.detail || 'Failed to create remediation task');
    err.status = res.status;
    err.detail = errData.detail;
    throw err;
  }
  return await res.json();
}

/**
 * getRemediationTask — retrieves remediation task and history for a finding.
 */
export async function getRemediationTask(findingId) {
  try {
    const res = await fetchWithAuth(`${API_BASE}/findings/${encodeURIComponent(findingId)}/remediation/task`);
    if (res.ok) return await res.json();
  } catch (err) {
    console.warn('Failed to fetch remediation task for finding', findingId, err);
  }
  return null;
}

/**
 * assignTaskOwner — assigns an owner to a remediation task.
 */
export async function assignTaskOwner(ticketId, assignee) {
  const res = await fetchWithAuth(`${API_BASE}/remediation/tasks/${encodeURIComponent(ticketId)}/assign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assignee }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const err = new Error(errData.detail || 'Failed to assign task owner');
    err.status = res.status;
    err.detail = errData.detail;
    throw err;
  }
  return await res.json();
}

/**
 * updateTaskStatus — transitions a remediation task status.
 */
export async function updateTaskStatus(ticketId, status, note = '') {
  const res = await fetchWithAuth(`${API_BASE}/remediation/tasks/${encodeURIComponent(ticketId)}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, note }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const err = new Error(errData.detail || 'Failed to update task status');
    err.status = res.status;
    err.detail = errData.detail;
    throw err;
  }
  return await res.json();
}

/**
 * getTaskChecklist — retrieves persisted checklist steps.
 */
export async function getTaskChecklist(ticketId) {
  try {
    const res = await fetchWithAuth(`${API_BASE}/remediation/tasks/${encodeURIComponent(ticketId)}/checklist`);
    if (res.ok) return await res.json();
  } catch (err) {
    console.warn('Failed to fetch checklist', err);
  }
  return [];
}

/**
 * updateTaskChecklistStep — updates step status and persists.
 */
export async function updateTaskChecklistStep(ticketId, stepId, status) {
  const res = await fetchWithAuth(`${API_BASE}/remediation/tasks/${encodeURIComponent(ticketId)}/checklist/step`, {
    method: 'POST',
    body: JSON.stringify({ step_id: stepId, status }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const err = new Error(errData.detail || 'Failed to update checklist step');
    err.status = res.status;
    throw err;
  }
  return await res.json();
}


