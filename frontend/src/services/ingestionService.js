/**
 * ingestionService.js — Phase 2 Ingestion & Scan-Run Pipeline API Client
 *
 * Calls versioned endpoints under `/api/v1/organizations/{org_id}/scan-runs/{scan_run_id}/...`.
 * Includes report file upload, API event ingestion, submission listing, stage events listing,
 * partial processing trigger, and scan-run scoped pipeline results retrieval.
 */

import { getAuthToken, API_BASE } from './findingsService';

function getAuthHeaders() {
  const token = getAuthToken();
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * Method A: Upload raw scanner report file (Multipart/form-data).
 */
export async function uploadScannerReport(orgId, scanRunId, scanner, file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}/ingest/${scanner}`, {
    method: 'POST',
    headers: getAuthHeaders(), // fetch automatically sets multipart boundary
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Report upload failed' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Method B: JSON / API Event Ingestion.
 */
export async function submitScannerApiEvent(orgId, scanRunId, scanner, payloadText, idempotencyKey = '') {
  const headers = {
    ...getAuthHeaders(),
    'Content-Type': 'application/json',
  };

  const res = await fetch(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}/events/${scanner}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ payload: payloadText, idempotency_key: idempotencyKey }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'API Event ingestion failed' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Fetch raw scanner submissions for a scan run.
 */
export async function getScanRunSubmissions(orgId, scanRunId) {
  const res = await fetch(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}/submissions`, {
    method: 'GET',
    headers: getAuthHeaders(),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch submissions' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Fetch real backend stage events for a scan run.
 */
export async function getScanRunEvents(orgId, scanRunId) {
  const res = await fetch(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}/events`, {
    method: 'GET',
    headers: getAuthHeaders(),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch stage events' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Privileged partial processing trigger for SECURITY_LEAD / ADMIN.
 */
export async function triggerScanRunProcessing(orgId, scanRunId) {
  const headers = {
    ...getAuthHeaders(),
    'Content-Type': 'application/json',
  };

  const res = await fetch(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}/process`, {
    method: 'POST',
    headers,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Processing trigger failed' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

/**
 * Retrieve final M1-M7 pipeline results scoped strictly to scan_run_id.
 */
export async function getScanRunResults(orgId, scanRunId) {
  const res = await fetch(`${API_BASE}/v1/organizations/${orgId}/scan-runs/${scanRunId}/results`, {
    method: 'GET',
    headers: getAuthHeaders(),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch scan run results' }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}
