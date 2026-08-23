import { describe, it, expect } from 'vitest';
import { generateInsights } from '../src/utils/insights';

describe('Security Insights Engine', () => {
  it('should generate critical insights for SLA breaches and critical findings', () => {
    const mockFindings = [
      { risk_level: 'CRITICAL', workflow: { status: 'OPEN', sla_status: 'BREACHED' } },
      { risk_level: 'HIGH', workflow: { status: 'OPEN', sla_status: 'ON_TRACK' } }
    ];
    const insights = generateInsights(mockFindings);
    expect(insights.map(i => i.id)).toContain('CRITICAL_COUNT');
    expect(insights.map(i => i.id)).toContain('SLA_BREACH');
  });

  it('should generate warning insights for unassigned critical assets', () => {
    const mockFindings = [
      {
        risk_level: 'HIGH',
        asset_criticality: 'CRITICAL',
        internet_exposure: true,
        workflow: { status: 'OPEN', assigned_to: null }
      }
    ];
    const insights = generateInsights(mockFindings);
    expect(insights.map(i => i.id)).toContain('INTERNET_CRITICAL');
    expect(insights.map(i => i.id)).toContain('UNASSIGNED');
  });
});
