import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  DATA_MODES,
  RUNTIME_STATUS,
  getDataMode,
  setDataMode,
  getRuntimeStatus,
  setRuntimeStatus,
  getDashboardSummary,
  getFindings,
  getFindingById,
  triggerPipelineRun,
} from '../src/services/findingsService';
import { getAssets } from '../src/services/assetsService';
import { getSLAItems } from '../src/services/slaService';

describe('Live/Mock Data Integrity & Runtime Status State Machine', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.clear();
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setDataMode(DATA_MODES.MOCK);
  });

  it('1. User selects MOCK -> status is immediately MOCK', () => {
    setDataMode(DATA_MODES.MOCK);
    expect(getDataMode()).toBe(DATA_MODES.MOCK);
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.MOCK);
  });

  it('2. User selects LIVE (INTEGRATED) -> status is CONNECTING before response', () => {
    setDataMode(DATA_MODES.INTEGRATED);
    expect(getDataMode()).toBe(DATA_MODES.INTEGRATED);
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.CONNECTING);
  });

  it('3. Valid live response -> establishes status LIVE', async () => {
    const mockLiveFindings = [
      {
        finding_id: 'DEDUP-LIVE-001',
        vulnerability_name: 'Live SQL Injection',
        risk_score: 95,
        risk_level: 'CRITICAL',
        workflow: { status: 'OPEN', sla_status: 'ON_TRACK' },
        detail: { asset_context: { asset_name: 'Payments Live' } },
      },
    ];

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockLiveFindings,
    });

    setDataMode(DATA_MODES.INTEGRATED);
    const data = await getFindings();

    expect(data).toHaveLength(1);
    expect(data[0].finding_id).toBe('DEDUP-LIVE-001');
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.LIVE);
  });

  it('4. Live API 500 error -> transitions honestly to FALLBACK', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ detail: 'Internal Server Error' }),
    });

    setDataMode(DATA_MODES.INTEGRATED);
    const data = await getFindings();

    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
    // In fallback mode, mock dataset is safely returned
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  });

  it('5. Network failure (fetch throws) -> transitions honestly to FALLBACK', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network connection refused (ECONNREFUSED)'));

    setDataMode(DATA_MODES.INTEGRATED);
    const summary = await getDashboardSummary();

    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
    expect(summary).toBeDefined();
    expect(summary.summary).toBeDefined();
  });

  it('6. Invalid / malformed live response (non-array for findings) -> transitions to FALLBACK', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ unexpected: 'not an array' }),
    });

    setDataMode(DATA_MODES.INTEGRATED);
    const findings = await getFindings();

    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
    // Fallback data provided
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('7. Fallback actually returns full mock dataset safely', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Backend down'));

    setDataMode(DATA_MODES.INTEGRATED);
    const findings = await getFindings();
    const summary = await getDashboardSummary();

    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
    expect(findings.length).toBeGreaterThan(0);
    expect(summary.summary.raw_findings).toBeGreaterThan(0);
  });

  it('8. Status is never LIVE when mock fallback data is displayed', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('503 Service Unavailable'));

    setDataMode(DATA_MODES.INTEGRATED);
    await getFindings();

    // MUST be FALLBACK, never LIVE
    expect(getRuntimeStatus()).not.toBe(RUNTIME_STATUS.LIVE);
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
  });

  it('9. Backend recovery: FALLBACK -> LIVE on successful subsequent fetch', async () => {
    // Phase 1: Backend down
    global.fetch = vi.fn().mockRejectedValue(new Error('503 Service Unavailable'));
    setDataMode(DATA_MODES.INTEGRATED);
    await getFindings();
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);

    // Phase 2: Backend restored
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [
        {
          finding_id: 'DEDUP-RESTORED-001',
          vulnerability_name: 'Restored Live Vuln',
          risk_score: 90,
          risk_level: 'CRITICAL',
          workflow: { status: 'OPEN', sla_status: 'ON_TRACK' },
        },
      ],
    });

    const liveData = await getFindings();
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.LIVE);
    expect(liveData[0].finding_id).toBe('DEDUP-RESTORED-001');
  });

  it('10. Manual MOCK mode remains MOCK and does not trigger live fetch', async () => {
    const fetchSpy = vi.fn();
    global.fetch = fetchSpy;

    setDataMode(DATA_MODES.MOCK);
    const findings = await getFindings();
    const summary = await getDashboardSummary();

    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.MOCK);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(findings.length).toBeGreaterThan(0);
    expect(summary.summary).toBeDefined();
  });

  it('11. Failed pipeline run (triggerPipelineRun) does NOT report successful LIVE execution', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ detail: 'Pipeline execution crashed in M3' }),
    });

    setDataMode(DATA_MODES.INTEGRATED);

    await expect(triggerPipelineRun()).rejects.toThrow();
    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
  });

  it('12. Assets and SLA derived services maintain consistent runtime data source', async () => {
    // Mock failure
    global.fetch = vi.fn().mockRejectedValue(new Error('Connection lost'));

    setDataMode(DATA_MODES.INTEGRATED);
    const assets = await getAssets();
    const sla = await getSLAItems();

    expect(getRuntimeStatus()).toBe(RUNTIME_STATUS.FALLBACK);
    expect(Array.isArray(assets)).toBe(true);
    expect(assets.length).toBeGreaterThan(0);
    expect(sla).toHaveProperty('ON_TRACK');
  });
});
