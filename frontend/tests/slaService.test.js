import { describe, it, expect, vi, beforeEach } from 'vitest';
import { deriveSLAItemsFromFindings, getTeamDisplayName, getRemediationTasks, getSLAItems, getBreachWarnings, getRemediationSummary } from '../src/services/slaService';
import * as findingsService from '../src/services/findingsService';

describe('SLA Service & Task Associations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

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

  it('resolves team display names correctly with fallback to handle', () => {
    expect(getTeamDisplayName('secops')).toBe('SOC Operations Team');
    expect(getTeamDisplayName('appsec-team')).toBe('Application Security Team');
    expect(getTeamDisplayName('payments-infra')).toBe('Payments Engineering');
    expect(getTeamDisplayName('unassigned')).toBe('Unassigned');
    expect(getTeamDisplayName(null)).toBe('Unassigned');
    expect(getTeamDisplayName('—')).toBe('Unassigned');
    expect(getTeamDisplayName('custom-team-lead')).toBe('custom-team-lead');
  });

  it('parses JSON properly in getRemediationTasks and returns array', async () => {
    const mockTaskData = [
      { ticket_id: 'TCK-22F4EDB43C', finding_id: 'DEDUP-90626421', assigned_to: 'secops', assignee_display_name: 'SOC Operations Team' }
    ];
    vi.spyOn(findingsService, 'fetchWithAuth').mockResolvedValue({
      ok: true,
      json: async () => mockTaskData
    });

    const tasks = await getRemediationTasks({ organization_id: 'ORG-RIZZOLVE-DEMO' });
    expect(Array.isArray(tasks)).toBe(true);
    expect(tasks.length).toBe(1);
    expect(tasks[0].ticket_id).toBe('TCK-22F4EDB43C');
    expect(tasks[0].assigned_to).toBe('secops');
  });

  it('handles getRemediationTasks network failure gracefully by returning empty array', async () => {
    vi.spyOn(findingsService, 'fetchWithAuth').mockRejectedValue(new Error('Network error'));
    const tasks = await getRemediationTasks();
    expect(Array.isArray(tasks)).toBe(true);
    expect(tasks.length).toBe(0);
  });
});
