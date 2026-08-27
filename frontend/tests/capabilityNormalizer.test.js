import { describe, it, expect } from 'vitest';
import { normalizeScannerKey, isScannerAvailableFromAgents } from '../src/utils/capabilityNormalizer';

describe('capabilityNormalizer', () => {
  it('normalizes canonical scanner keys and aliases', () => {
    expect(normalizeScannerKey('NUCLEI')).toBe('NUCLEI');
    expect(normalizeScannerKey('nuclei')).toBe('NUCLEI');
    expect(normalizeScannerKey('Nuclei')).toBe('NUCLEI');

    expect(normalizeScannerKey('ZAP')).toBe('ZAP');
    expect(normalizeScannerKey('zap')).toBe('ZAP');
    expect(normalizeScannerKey('OWASP ZAP')).toBe('ZAP');
    expect(normalizeScannerKey('OWASP_ZAP')).toBe('ZAP');

    expect(normalizeScannerKey('WAPITI')).toBe('WAPITI');
    expect(normalizeScannerKey('wapiti')).toBe('WAPITI');
    expect(normalizeScannerKey('Wapiti')).toBe('WAPITI');

    expect(normalizeScannerKey('UNKNOWN')).toBeNull();
    expect(normalizeScannerKey('')).toBeNull();
    expect(normalizeScannerKey(null)).toBeNull();
  });

  it('determines scanner availability from dict of objects schema', () => {
    const agents = [
      {
        status: 'ACTIVE',
        capabilities_json: JSON.stringify({
          NUCLEI: { available: true, version: 'v3.3.8' },
          ZAP: { available: true, version: '2.16.0' },
          WAPITI: { available: true, version: '3.2.3' }
        })
      }
    ];

    expect(isScannerAvailableFromAgents(agents, 'NUCLEI')).toBe(true);
    expect(isScannerAvailableFromAgents(agents, 'ZAP')).toBe(true);
    expect(isScannerAvailableFromAgents(agents, 'WAPITI')).toBe(true);
  });

  it('determines availability from legacy list schema and aliases', () => {
    const agents = [
      {
        status: 'ACTIVE',
        capabilities_json: ['OWASP ZAP', 'nuclei', 'Wapiti']
      }
    ];

    expect(isScannerAvailableFromAgents(agents, 'NUCLEI')).toBe(true);
    expect(isScannerAvailableFromAgents(agents, 'ZAP')).toBe(true);
    expect(isScannerAvailableFromAgents(agents, 'WAPITI')).toBe(true);
  });

  it('excludes revoked or inactive agents', () => {
    const agents = [
      {
        status: 'REVOKED',
        capabilities_json: JSON.stringify({
          ZAP: { available: true },
          WAPITI: { available: true }
        })
      }
    ];

    expect(isScannerAvailableFromAgents(agents, 'ZAP')).toBe(false);
    expect(isScannerAvailableFromAgents(agents, 'WAPITI')).toBe(false);
  });

  it('handles missing or explicit false available flag', () => {
    const agents = [
      {
        status: 'ACTIVE',
        capabilities_json: JSON.stringify({
          NUCLEI: { version: '3.3.8' },
          ZAP: { available: false },
          WAPITI: { available: true }
        })
      }
    ];

    expect(isScannerAvailableFromAgents(agents, 'NUCLEI')).toBe(false);
    expect(isScannerAvailableFromAgents(agents, 'ZAP')).toBe(false);
    expect(isScannerAvailableFromAgents(agents, 'WAPITI')).toBe(true);
  });
});
