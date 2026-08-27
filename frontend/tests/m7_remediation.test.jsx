import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Finding360 from '../src/pages/Finding360';
import * as findingsService from '../src/services/findingsService';

const mockFinding = {
  finding_id: 'DEDUP-90626421',
  cve_id: 'CVE-2021-44228',
  vulnerability_name: 'Apache Log4j Remote Code Execution (Log4Shell)',
  risk_score: 95,
  risk_level: 'CRITICAL',
  confidence_classification: 'High Confidence',
  asset_id: 'ASSET-DA1A14B2CF',
  asset_criticality: 'CRITICAL',
  internet_exposure: true,
  recommended_action: 'Upgrade log4j-core to 2.17.1 or newer.',
  workflow: {
    ticket_id: 'TCK-LOG4J-01',
    status: 'OPEN',
    assigned_to: null,
    sla_hours: 4,
    sla_due_at: new Date(Date.now() + 4 * 3600 * 1000).toISOString(),
    sla_status: 'ON_TRACK',
    escalation_level: 0,
  },
  detail: {
    scanner_consensus: {
      score: 1.0,
      scanner_names: ['Nuclei'],
      detected_by_count: 1,
      total_scanners: 3,
    },
    finding_confidence: {
      score: 0.95,
      classification: 'High Confidence',
    },
    threat_intelligence: {
      cvss_score: 10.0,
      epss_score: 0.97,
      kev_listed: true,
      exploit_available: true,
    },
    asset_context: {
      asset_name: 'Payment Gateway Service',
      environment: 'PRODUCTION',
      criticality: 'CRITICAL',
      internet_facing: true,
      data_sensitivity: 'CONFIDENTIAL',
    },
    provenance: {
      source_findings: [
        { finding_id: 'SRC-NUCLEI-01', scanner: 'Nuclei' },
      ],
    },
  },
};

describe('Finding360 M7 Remediation & SLA Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockFinding);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      id: 'analyst-1',
      name: 'Analyst Jane',
      role: 'ANALYST',
      organization_id: 'ORG-RIZZOLVE-DEMO',
    });
    vi.spyOn(findingsService, 'getRemediationTask').mockResolvedValue({
      ticket: {
        ticket_id: 'TCK-LOG4J-01',
        organization_id: 'ORG-RIZZOLVE-DEMO',
        finding_id: 'DEDUP-90626421',
        priority: 'CRITICAL',
        sla_hours: 4,
        due_at: new Date(Date.now() + 3.5 * 3600 * 1000).toISOString(),
        status: 'OPEN',
        assigned_to: null,
      },
      history: [],
    });
  });

  it('renders live server-derived SLA remaining countdown and deadline', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Apache Log4j Remote Code Execution/i)[0]).toBeInTheDocument();
    });

    // Check SLA remaining countdown exists and does not contain broken static text
    const slaRemainingElements = screen.getAllByText(/SLA Remaining/i);
    expect(slaRemainingElements.length).toBeGreaterThan(0);
    expect(screen.queryByText(/03h 42m/i)).not.toBeInTheDocument(); // No hardcoded fallback
  });

  it('supports interactive owner assignment without browser alert', async () => {
    const assignSpy = vi.spyOn(findingsService, 'assignTaskOwner').mockResolvedValue({
      status: 'success',
      ticket: {
        ticket_id: 'TCK-LOG4J-01',
        organization_id: 'ORG-RIZZOLVE-DEMO',
        finding_id: 'DEDUP-90626421',
        status: 'ASSIGNED',
        assigned_to: 'secops',
      },
      history: [],
    });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Apache Log4j/i)[0]).toBeInTheDocument();
    });

    const assignBtn = screen.getByTitle('Assign Owner');
    fireEvent.click(assignBtn);

    // Popover appears
    expect(screen.getByText(/Assign Remediation Owner/i)).toBeInTheDocument();
    const confirmBtn = screen.getByText(/Confirm Assignment/i);
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(assignSpy).toHaveBeenCalledWith('TCK-LOG4J-01', 'secops');
    });
  });

  it('allows switching to Remediation tab and viewing remediation plan & task card', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Apache Log4j/i)[0]).toBeInTheDocument();
    });

    const remTabBtn = screen.getAllByRole('button', { name: /Remediation/i })[0];
    fireEvent.click(remTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Remediation Guidance/i)).toBeInTheDocument();
      expect(screen.getByText(/Remediation Plan & Tasks/i)).toBeInTheDocument();
      expect(screen.getByText(/Task ID:/i)).toBeInTheDocument();
    });
  });
});
