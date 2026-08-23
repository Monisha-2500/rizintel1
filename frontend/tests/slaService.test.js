import { describe, it, expect } from 'vitest';
import { deriveSLAItemsFromFindings } from '../src/services/slaService';

describe('SLA Grouping Service', () => {
  it('should categorize findings into correct SLA buckets', () => {
    const mockFindings = [
      { finding_id: '1', risk_score: 90, workflow: { sla_status: 'BREACHED' } },
      { finding_id: '2', risk_score: 80, workflow: { sla_status: 'AT_RISK' } },
      { finding_id: '3', risk_score: 70, workflow: { sla_status: 'ON_TRACK' } },
      { finding_id: '4', risk_score: 60, workflow: { sla_status: 'MET' } }
    ];

    const grouped = deriveSLAItemsFromFindings(mockFindings);
    expect(grouped.BREACHED.length).toBe(1);
    expect(grouped.BREACHED[0].finding_id).toBe('1');
    
    expect(grouped.AT_RISK.length).toBe(1);
    expect(grouped.AT_RISK[0].finding_id).toBe('2');

    expect(grouped.ON_TRACK.length).toBe(1);
    expect(grouped.ON_TRACK[0].finding_id).toBe('3');

    expect(grouped.MET.length).toBe(1);
    expect(grouped.MET[0].finding_id).toBe('4');
  });
});
