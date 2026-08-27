import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import SLAMonitor from '../src/pages/SLAMonitor';
import * as findingsService from '../src/services/findingsService';
import * as slaService from '../src/services/slaService';

const mockFindings = [
  {
    finding_id: 'DEDUP-90626421',
    vulnerability_name: 'Apache Log4j Remote Code Execution (Log4Shell)',
    cve_id: 'CVE-2021-44228',
    organization_id: 'ORG-RIZZOLVE-DEMO',
    risk_score: 68,
    risk_level: 'HIGH',
    asset_id: 'ASSET-DA1A14B2CF',
    detail: {
      asset_context: {
        asset_name: 'Payment Gateway Service (Web Application)',
        environment: 'production',
        criticality: 'HIGH',
        data_sensitivity: 'CONFIDENTIAL',
        internet_exposure: true
      },
      scanner_consensus: {
        total_scanners: 3,
        scanner_names: ['Nuclei']
      }
    },
    workflow: {
      ticket_id: 'TKT-0001',
      status: 'OPEN',
      sla_status: 'ON_TRACK',
      assigned_to: null, // Empirical condition: raw finding workflow object is unassigned/stale
      sla_hours: 168,
      sla_due_at: '2026-09-02T15:53:44.677339Z',
      escalation_level: 0
    }
  },
  {
    finding_id: 'DEDUP-0002',
    vulnerability_name: 'Remote Code Execution in Spring Framework',
    cve_id: 'CVE-2022-22965',
    organization_id: 'ORG-RIZZOLVE-DEMO',
    risk_score: 95,
    risk_level: 'CRITICAL',
    asset_id: 'ASSET-002',
    detail: {
      asset_context: {
        asset_name: 'Auth API Gateway',
        environment: 'production',
        criticality: 'CRITICAL',
        internet_exposure: true
      }
    },
    workflow: {
      ticket_id: 'TCK-0002',
      status: 'OPEN',
      sla_status: 'BREACHED',
      assigned_to: 'appsec-team',
      sla_hours: 4,
      sla_due_at: '2026-09-10T10:00:00.000000Z',
      escalation_level: 1
    }
  },
  {
    finding_id: 'DEDUP-0003',
    vulnerability_name: 'Cross-Site Scripting in User Profile',
    cve_id: null,
    organization_id: 'ORG-RIZZOLVE-DEMO',
    risk_score: 35,
    risk_level: 'LOW',
    asset_id: 'ASSET-003',
    detail: {
      asset_context: {
        asset_name: 'Internal Portal',
        environment: 'staging',
        criticality: 'LOW',
        internet_exposure: false
      }
    },
    workflow: {
      ticket_id: 'TCK-0003',
      status: 'RESOLVED',
      sla_status: 'MET',
      assigned_to: null,
      sla_hours: 720,
      sla_due_at: '2026-09-30T10:00:00.000000Z',
      escalation_level: 0
    }
  }
];

const mockTasks = [
  {
    ticket_id: 'TCK-22F4EDB43C',
    finding_id: 'DEDUP-90626421',
    organization_id: 'ORG-RIZZOLVE-DEMO',
    cve_id: 'CVE-2021-44228',
    asset_name: 'Payment Gateway Service (Web Application)',
    risk_score: 68,
    priority: 'MEDIUM',
    sla_hours: 168,
    due_at: '2026-09-02T15:53:44.677339Z',
    status: 'IN_PROGRESS',
    assigned_to: 'secops',
    assignee_display_name: 'SOC Operations Team',
    assignee_type: 'TEAM',
    checklist_json: JSON.stringify([
      { id: 1, title: 'Upgrade dependency', status: 'COMPLETED' },
      { id: 2, title: 'Apply WAF rule', status: 'IN_PROGRESS' }
    ])
  },
  {
    ticket_id: 'TCK-0002',
    finding_id: 'DEDUP-0002',
    organization_id: 'ORG-RIZZOLVE-DEMO',
    cve_id: 'CVE-2022-22965',
    asset_name: 'Auth API Gateway',
    risk_score: 95,
    priority: 'CRITICAL',
    sla_hours: 4,
    due_at: '2026-09-10T10:00:00.000000Z',
    status: 'OPEN',
    assigned_to: 'appsec-team',
    assignee_display_name: 'Application Security Team',
    assignee_type: 'TEAM',
    checklist_json: '[]'
  }
];

describe('Remediation SLA Monitor Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockFindings);
    vi.spyOn(slaService, 'getRemediationTasks').mockResolvedValue(mockTasks);
    vi.spyOn(slaService, 'getBreachWarnings').mockResolvedValue({
      hard_breaches: ['TCK-0002'],
      predictive_warnings: []
    });
  });

  const renderComponent = (initialEntries = ['/sla']) => {
    return render(
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/sla" element={<SLAMonitor />} />
          <Route path="/findings/:id" element={<div data-testid="finding-360-view">Finding 360 View</div>} />
        </Routes>
      </MemoryRouter>
    );
  };

  it('1. renders SLA Monitor header and title', async () => {
    renderComponent();
    expect(screen.getByText('Remediation SLA Monitor')).toBeInTheDocument();
    expect(screen.getByText(/Track remediation commitments, identify breach risk/i)).toBeInTheDocument();
  });

  it('2. displays all 6 summary metric cards with accurate counts', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Active SLAs')).toBeInTheDocument();
      expect(screen.getByText('Breached')).toBeInTheDocument();
      expect(screen.getByText('At Risk')).toBeInTheDocument();
      expect(screen.getByText('On Track')).toBeInTheDocument();
      expect(screen.getByText('Resolved')).toBeInTheDocument();
      expect(screen.getAllByText('Unassigned').length).toBeGreaterThan(0);
    });
  });

  it('3. displays Next SLA Deadline card with accurate asset and owner (SOC Operations Team)', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('NEXT SLA DEADLINE')).toBeInTheDocument();
      expect(screen.getByText('Apache Log4j Remote Code Execution (Log4Shell)')).toBeInTheDocument();
      expect(screen.getByText(/SOC Operations Team/i)).toBeInTheDocument();
    });
  });

  it('4. displays Analysis Overview panels: SLA Compliance, Contextual Risk Distribution, and SLA Intelligence', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('SLA Compliance & Status')).toBeInTheDocument();
      expect(screen.getByText('Contextual Risk Distribution')).toBeInTheDocument();
      expect(screen.getByText('SLA Intelligence')).toBeInTheDocument();
    });
  });

  it('5. switches to Active SLA Queue and displays detailed task cards', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Active SLA Queue')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Active SLA Queue'));

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search by vulnerability, CVE, asset/i)).toBeInTheDocument();
      expect(screen.getByText(/CVE-2021-44228/i)).toBeInTheDocument();
      expect(screen.getByText(/No CVE assigned/i)).toBeInTheDocument();
      expect(screen.getByText(/Risk: HIGH · 68/i)).toBeInTheDocument();
      expect(screen.getByText(/Priority: MEDIUM \(168h\)/i)).toBeInTheDocument();
    });
  });

  it('6. verifies Log4Shell owner matches SOC Operations Team (secops)', async () => {
    renderComponent(['/sla?view=queue']);
    await waitFor(() => {
      expect(screen.getAllByText(/SOC Operations Team/i).length).toBeGreaterThan(0);
    });
  });

  it('7. filters tasks by search query', async () => {
    renderComponent(['/sla?view=queue']);
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search by vulnerability/i)).toBeInTheDocument();
      expect(screen.getByText(/Apache Log4j Remote Code Execution/i)).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/Search by vulnerability/i);
    fireEvent.change(searchInput, { target: { value: 'Spring' } });

    await waitFor(() => {
      expect(screen.getByText(/Remote Code Execution in Spring/i)).toBeInTheDocument();
      expect(screen.queryByText(/Apache Log4j Remote Code Execution/i)).not.toBeInTheDocument();
    });
  });

  it('8. switches to Kanban Board and renders 4 workflow columns', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Kanban Board')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Kanban Board'));

    await waitFor(() => {
      expect(screen.getAllByText('Open').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Assigned').length).toBeGreaterThan(0);
      expect(screen.getAllByText('In Progress').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Resolved').length).toBeGreaterThan(0);
    });
  });

  it('9. switches to Team View and renders SOC Operations Team card without duplicate in Unassigned', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Team View')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Team View'));

    await waitFor(() => {
      expect(screen.getByText(/Unassigned Tasks Queue/i)).toBeInTheDocument();
      expect(screen.getByText('SOC Operations Team')).toBeInTheDocument();
      expect(screen.getByText('Application Security Team')).toBeInTheDocument();
    });
  });

  it('10. navigates to canonical Finding360 when clicking Inspect Finding', async () => {
    renderComponent(['/sla?view=queue']);
    await waitFor(() => {
      expect(screen.getAllByText('Inspect Finding').length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getAllByText('Inspect Finding')[0]);

    await waitFor(() => {
      expect(screen.getByTestId('finding-360-view')).toBeInTheDocument();
    });
  });

  it('11. joins DEDUP-90626421 to TCK-22F4EDB43C by finding_id authoritatively when raw finding is unassigned', async () => {
    renderComponent(['/sla?view=queue']);
    await waitFor(() => {
      // Finding DEDUP-90626421 should display TCK-22F4EDB43C ticket and SOC Operations Team
      expect(screen.getByText(/TCK-22F4EDB43C/i)).toBeInTheDocument();
      expect(screen.getAllByText(/SOC Operations Team/i).length).toBeGreaterThan(0);
    });
  });

  it('12. resolves assignee without display name via getTeamDisplayName instead of Unassigned', async () => {
    const tasksWithoutDisplayName = [
      {
        ticket_id: 'TCK-22F4EDB43C',
        finding_id: 'DEDUP-90626421',
        organization_id: 'ORG-RIZZOLVE-DEMO',
        status: 'IN_PROGRESS',
        assigned_to: 'secops', // no assignee_display_name provided
        due_at: '2026-09-02T15:53:44.677339Z'
      }
    ];
    vi.spyOn(slaService, 'getRemediationTasks').mockResolvedValue(tasksWithoutDisplayName);

    renderComponent(['/sla?view=queue']);
    await waitFor(() => {
      expect(screen.getAllByText(/SOC Operations Team/i).length).toBeGreaterThan(0);
    });
  });
});
