/**
 * workspaceService.js — Workspace & Operational API Client (Phase 1)
 *
 * Calls versioned endpoints under `/api/v1/organizations`.
 * Attaches Authorization header via `getAuthToken()`.
 */

import { getAuthToken, API_BASE, fetchWithAuth } from './findingsService';

function getHeaders() {
  const token = getAuthToken();
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * Fetch all organizations the logged-in user belongs to.
 */
export async function getMyOrganizations() {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch organizations' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Fetch detail for a specific organization.
 */
export async function getOrganizationDetail(orgId) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch organization' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * List registered assets for an organization.
 */
export async function getRegisteredAssets(orgId) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}/assets`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch registered assets' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Register a new asset (SECURITY_LEAD / ADMIN required).
 */
export async function registerAsset(orgId, assetData) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}/assets`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(assetData),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Asset registration failed' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Patch asset authorization status (PENDING / AUTHORIZED / DISABLED).
 */
export async function updateAssetStatus(orgId, assetId, status) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}/assets/${assetId}`, {
    method: 'PATCH',
    headers: getHeaders(),
    body: JSON.stringify({ authorization_status: status }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Status update failed' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * List scan runs for an organization.
 */
export async function getScanRuns(orgId) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}/scan-runs`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch scan runs' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Fetch a single scan run for an organization.
 */
export async function getScanRun(orgId, scanRunId) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch scan run' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Create a new scan run (ANALYST / LEAD / ADMIN required).
 */
export async function createScanRun(orgId, scanData) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${orgId}/scan-runs`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(scanData),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan run creation failed' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}
