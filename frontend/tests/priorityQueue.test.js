import { describe, it, expect } from 'vitest';
import { sortFindings, MaxFindingHeap } from '../src/utils/priorityQueue';

describe('Priority Queue and Sorting Algorithm', () => {
  const mockFindings = [
    {
      finding_id: 'V1',
      risk_score: 80,
      workflow: { sla_status: 'ON_TRACK' },
      detail: { finding_confidence: { score: 0.8 }, threat_intelligence: { epss_score: 0.1 } }
    },
    {
      finding_id: 'V2',
      risk_score: 95,
      workflow: { sla_status: 'ON_TRACK' },
      detail: { finding_confidence: { score: 0.9 }, threat_intelligence: { epss_score: 0.5 } }
    },
    {
      finding_id: 'V3', // Tie-breaker check: Same risk_score as V2, but BREACHED (higher SLA urgency)
      risk_score: 95,
      workflow: { sla_status: 'BREACHED' },
      detail: { finding_confidence: { score: 0.9 }, threat_intelligence: { epss_score: 0.5 } }
    },
    {
      finding_id: 'V4', // Tie-breaker check: Same risk & SLA status as V2, but higher confidence score
      risk_score: 95,
      workflow: { sla_status: 'ON_TRACK' },
      detail: { finding_confidence: { score: 0.98 }, threat_intelligence: { epss_score: 0.5 } }
    },
    {
      finding_id: 'V5', // Tie-breaker check: Same risk, SLA, conf as V2, but higher EPSS
      risk_score: 95,
      workflow: { sla_status: 'ON_TRACK' },
      detail: { finding_confidence: { score: 0.9 }, threat_intelligence: { epss_score: 0.8 } }
    }
  ];

  it('should sort findings with highest risk_score first', () => {
    const sorted = sortFindings(mockFindings);
    expect(sorted[0].finding_id).toBe('V3'); // 95 risk + BREACHED
    expect(sorted[4].finding_id).toBe('V1'); // 80 risk
  });

  it('should resolve ties using SLA status → finding confidence → EPSS', () => {
    const sorted = sortFindings(mockFindings);
    
    // V3 (SLA BREACHED) should be #1
    expect(sorted[0].finding_id).toBe('V3');
    
    // V4 (Confidence 0.98) should be #2 (beats V5 & V2)
    expect(sorted[1].finding_id).toBe('V4');
    
    // V5 (EPSS 0.8) should be #3 (beats V2)
    expect(sorted[2].finding_id).toBe('V5');
    
    // V2 should be #4
    expect(sorted[3].finding_id).toBe('V2');
  });

  it('should support binary MaxFindingHeap operations correctly', () => {
    const heap = new MaxFindingHeap();
    mockFindings.forEach(f => heap.insert(f));

    expect(heap.size()).toBe(5);
    expect(heap.peek().finding_id).toBe('V3');
    
    const drained = heap.drainSorted();
    expect(drained[0].finding_id).toBe('V3');
    expect(drained[1].finding_id).toBe('V4');
    expect(drained[2].finding_id).toBe('V5');
    expect(drained[3].finding_id).toBe('V2');
    expect(drained[4].finding_id).toBe('V1');
  });
});
