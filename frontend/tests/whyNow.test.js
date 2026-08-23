import { describe, it, expect } from 'vitest';
import { generateWhyNowReasons } from '../src/utils/whyNow';

describe('Why Now? Reason Generation Engine', () => {
  it('should generate critical reasons for KEV and high EPSS', () => {
    const finding = {
      finding_id: 'F1',
      asset_criticality: 'MEDIUM',
      detail: {
        threat_intelligence: {
          kev_listed: true,
          epss_score: 0.95,
          exploit_available: true
        }
      }
    };
    const reasons = generateWhyNowReasons(finding);
    expect(reasons.map(r => r.id)).toContain('KEV');
    expect(reasons.map(r => r.id)).toContain('EPSS');
    expect(reasons.map(r => r.id)).toContain('EXPLOIT');
    expect(reasons.every(r => r.severity === 'critical')).toBe(true);
  });

  it('should generate warning reasons for critical assets and internet exposure', () => {
    const finding = {
      finding_id: 'F2',
      asset_criticality: 'CRITICAL',
      internet_exposure: true,
      detail: {
        threat_intelligence: {
          kev_listed: false,
          epss_score: 0.1
        }
      }
    };
    const reasons = generateWhyNowReasons(finding);
    expect(reasons.map(r => r.id)).toContain('CRITICAL_ASSET');
    expect(reasons.map(r => r.id)).toContain('INTERNET');
  });
});
