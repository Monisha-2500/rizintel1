/**
 * agentService.js — Scanner Agents API Service (Phase 4)
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

export async function listScannerAgents(organizationId) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${organizationId}/scanner-agents`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch scanner agents' }));
    throw new Error(err.detail || 'Failed to fetch scanner agents');
  }
  return res.json();
}

export async function registerScannerAgent(organizationId, displayName, capabilities = null) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${organizationId}/scanner-agents`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({
      display_name: displayName,
      capabilities,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to register scanner agent' }));
    throw new Error(err.detail || 'Failed to register scanner agent');
  }
  return res.json();
}

export async function revokeScannerAgent(organizationId, agentId) {
  const res = await fetchWithAuth(`${API_BASE}/v1/organizations/${organizationId}/scanner-agents/${agentId}/revoke`, {
    method: 'POST',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to revoke scanner agent' }));
    throw new Error(err.detail || 'Failed to revoke scanner agent');
  }
  return res.json();
}
