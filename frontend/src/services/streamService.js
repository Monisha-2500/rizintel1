/**
 * streamService.js — Real-Time Server-Sent Events (SSE) Client Service (Phase 3)
 *
 * Responsibilities:
 * - Issues short-lived stream tokens or attaches JWT for authenticated SSE streaming.
 * - Enforces organization membership and scan-run tenant isolation.
 * - Tracks Last-Event-ID cursor to replay missed events upon reconnection.
 * - Exposes connection health states: LIVE | RECONNECTING | DISCONNECTED.
 * - Emits callbacks for scanner status, pipeline stage transitions, counts, completed, failed, and heartbeats.
 */

import { API_BASE, getAuthToken } from './findingsService';

/**
 * issueStreamToken — fetches short-lived (90s) SSE stream ticket for EventSource.
 */
export async function issueStreamToken(orgId, scanRunId) {
  const token = getAuthToken();
  const res = await fetch(`${API_BASE}/v1/organizations/${encodeURIComponent(orgId)}/scan-runs/${encodeURIComponent(scanRunId)}/stream-token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {}
    throw new Error(`Failed to issue stream token: ${detail}`);
  }

  return await res.json();
}

/**
 * subscribeToScanRunStream — establishes live SSE subscription for a ScanRun.
 *
 * @param {string} orgId
 * @param {string} scanRunId
 * @param {Object} callbacks
 * @returns {Function} unsubscribe function
 */
export function subscribeToScanRunStream(orgId, scanRunId, callbacks = {}) {
  let eventSource = null;
  let isClosed = false;
  let lastEventId = null;
  let reconnectTimer = null;

  const notifyConnection = (status) => {
    if (callbacks.onConnectionChange) {
      callbacks.onConnectionChange(status);
    }
  };

  const connect = async () => {
    if (isClosed) return;
    notifyConnection('CONNECTING');

    const authToken = getAuthToken();
    let streamUrl = `${API_BASE}/v1/organizations/${encodeURIComponent(orgId)}/scan-runs/${encodeURIComponent(scanRunId)}/stream`;

    // Try issuing stream token if available, otherwise append JWT token query param
    try {
      const ticket = await issueStreamToken(orgId, scanRunId);
      streamUrl += `?stream_token=${encodeURIComponent(ticket.stream_token)}`;
    } catch (e) {
      if (authToken) {
        streamUrl += `?token=${encodeURIComponent(authToken)}`;
      }
    }

    if (lastEventId) {
      const sep = streamUrl.includes('?') ? '&' : '?';
      streamUrl += `${sep}last_event_id=${encodeURIComponent(lastEventId)}`;
    }

    try {
      eventSource = new EventSource(streamUrl);
    } catch (err) {
      console.warn('Failed to construct EventSource:', err);
      notifyConnection('RECONNECTING');
      scheduleReconnect();
      return;
    }

    eventSource.onopen = () => {
      if (isClosed) return;
      notifyConnection('LIVE');
    };

    eventSource.onerror = (err) => {
      if (isClosed) return;
      console.warn('SSE Stream disconnected/error:', err);
      notifyConnection('RECONNECTING');
      if (eventSource) {
        eventSource.close();
      }
      scheduleReconnect();
    };

    // Generic snapshot / scan_run event
    eventSource.addEventListener('scan_run', (e) => {
      if (isClosed) return;
      if (e.lastEventId) lastEventId = e.lastEventId;
      try {
        const data = JSON.parse(e.data);
        if (data.event_id) lastEventId = data.event_id;
        if (data.snapshot && callbacks.onSnapshot) {
          callbacks.onSnapshot(data.snapshot);
        }
        if (callbacks.onScanRun) {
          callbacks.onScanRun(data);
        }
      } catch (err) {
        console.error('Failed to parse scan_run event:', err);
      }
    });

    // Scanner status event
    eventSource.addEventListener('scanner_status', (e) => {
      if (isClosed) return;
      if (e.lastEventId) lastEventId = e.lastEventId;
      try {
        const data = JSON.parse(e.data);
        if (data.event_id) lastEventId = data.event_id;
        if (callbacks.onScannerStatus) {
          callbacks.onScannerStatus(data);
        }
      } catch (err) {
        console.error('Failed to parse scanner_status event:', err);
      }
    });

    // Pipeline stage event
    eventSource.addEventListener('pipeline_stage', (e) => {
      if (isClosed) return;
      if (e.lastEventId) lastEventId = e.lastEventId;
      try {
        const data = JSON.parse(e.data);
        if (data.event_id) lastEventId = data.event_id;
        if (callbacks.onPipelineStage) {
          callbacks.onPipelineStage(data);
        }
      } catch (err) {
        console.error('Failed to parse pipeline_stage event:', err);
      }
    });

    // Counts event
    eventSource.addEventListener('counts', (e) => {
      if (isClosed) return;
      if (e.lastEventId) lastEventId = e.lastEventId;
      try {
        const data = JSON.parse(e.data);
        if (data.event_id) lastEventId = data.event_id;
        if (callbacks.onCounts) {
          callbacks.onCounts(data);
        }
      } catch (err) {
        console.error('Failed to parse counts event:', err);
      }
    });

    // Completed event
    eventSource.addEventListener('completed', (e) => {
      if (isClosed) return;
      if (e.lastEventId) lastEventId = e.lastEventId;
      try {
        const data = JSON.parse(e.data);
        if (data.event_id) lastEventId = data.event_id;
        if (callbacks.onCompleted) {
          callbacks.onCompleted(data);
        }
      } catch (err) {
        console.error('Failed to parse completed event:', err);
      }
    });

    // Failed event
    eventSource.addEventListener('failed', (e) => {
      if (isClosed) return;
      if (e.lastEventId) lastEventId = e.lastEventId;
      try {
        const data = JSON.parse(e.data);
        if (data.event_id) lastEventId = data.event_id;
        if (callbacks.onFailed) {
          callbacks.onFailed(data);
        }
      } catch (err) {
        console.error('Failed to parse failed event:', err);
      }
    });

    // Heartbeat event
    eventSource.addEventListener('heartbeat', (e) => {
      if (isClosed) return;
      try {
        const data = JSON.parse(e.data);
        if (callbacks.onHeartbeat) {
          callbacks.onHeartbeat(data);
        }
      } catch {}
    });
  };

  const scheduleReconnect = () => {
    if (isClosed) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(() => {
      connect();
    }, 2000);
  };

  connect();

  return () => {
    isClosed = true;
    notifyConnection('DISCONNECTED');
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (eventSource) {
      eventSource.close();
    }
  };
}
