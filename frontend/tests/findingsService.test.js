import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { getFindingById, getAssetDisplayName, setDataMode, DATA_MODES } from '../src/services/findingsService';

describe('Findings Service and Asset Name Lookup', () => {
  // Pin tests to MOCK mode so they do not require a running backend
  beforeEach(() => setDataMode(DATA_MODES.MOCK));
  afterEach(() => setDataMode(DATA_MODES.MOCK));

  it('should resolve friendly asset display names from asset IDs', () => {
    expect(getAssetDisplayName('ASSET-PAY-001')).toBe('Fee Payment API');
    expect(getAssetDisplayName('ASSET-WEB-001')).toBe('Payments Production API');
    expect(getAssetDisplayName('ASSET-UNKNOWN')).toBe('ASSET-UNKNOWN');
  });

  it('should fetch single finding by ID in mock mode', async () => {
    const f = await getFindingById('DEDUP-0001');
    expect(f).not.toBeNull();
    expect(f.finding_id).toBe('DEDUP-0001');
    expect(f.vulnerability_name).toBe('SQL Injection');
  });

  it('should return null for non-existing finding ID', async () => {
    const f = await getFindingById('DEDUP-9999');
    expect(f).toBeNull();
  });
});

