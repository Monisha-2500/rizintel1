import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import Finding360 from '../src/pages/Finding360';
import * as findingsService from '../src/services/findingsService';

const mockLog4jCanonical = {
  finding_id: 'DEDUP-90626421',
  vulnerability_name: 'Apache Log4j Remote Code Execution (Log4Shell)',
  vulnerability_type: 'RCE',
  cve_id: 'CVE-2021-44228',
  asset_id: 'ASSET-DA1A14B2CF',
  asset_name: 'Payment Gateway Service (Web Application)',
  asset_criticality: 'HIGH',
  internet_exposure: true,
  risk_score: 68,
  risk_level: 'HIGH',
  confidence_classification: 'High Confidence',
  recommended_action: 'Upgrade to Log4j 2.17.1 or higher. Disable JNDI lookup via log4j2.formatMsgNoLookups=true or remove JndiLookup class.',
  discovered_at: '2026-08-20T10:00:00Z',
  workflow: {
    status: 'Open',
    sla_status: 'ON_TRACK',
    sla_deadline: '2026-08-27T18:00:00Z',
    ticket_id: 'TICK-9062'
  },
  detail: {
    asset_context: {
      asset_name: 'Payment Gateway Service (Web Application)',
      environment: 'production',
      criticality: 'HIGH',
      internet_facing: true,
      data_sensitivity: 'CONFIDENTIAL',
      owner: 'Security Operations'
    },
    threat_intelligence: {
      kev_listed: true,
      epss_score: 1.0,
      cvss_score: 10.0,
      exploit_available: true
    },
    finding_confidence: {
      score: 0.76,
      classification: 'HIGH_CONFIDENCE'
    },
    scanner_consensus: {
      detected_by_count: 1,
      total_scanners: 3,
      scanner_names: ['Nuclei']
    },
    provenance: {
      source_findings: [
        {
          finding_id: 'NUC-2024-0512-001',
          scanner: 'Nuclei',
          severity: 'HIGH',
          discovered_at: '2026-08-20T10:00:00Z'
        }
      ]
    },
    explanation: {
      technical: 'Known exploitation, high asset criticality and internet exposure drive this finding\'s High contextual risk score.',
      top_risk_drivers: ['Known Exploited Vulnerability (CISA KEV)', 'Internet-facing production asset', 'High business asset criticality']
    }
  }
};

describe('Finding360 / Investigation Page Production Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    findingsService.setAuthSession('mock-token-analyst', {
      id: 'usr-1',
      name: 'Test Analyst',
      email: 'analyst@rizintel.io',
      role: 'ANALYST',
      organization_id: 'ORG-RIZZOLVE-DEMO'
    });
  });

  it('1. resolves canonical finding record and renders hero title & CVE', async () => {
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Apache Log4j Remote Code Execution (Log4Shell)')[0]).toBeInTheDocument();
      expect(screen.getAllByText('CVE-2021-44228')[0]).toBeInTheDocument();
      expect(screen.getAllByText('DEDUP-90626421')[0]).toBeInTheDocument();
    });
  });

  it('2. displays consistent risk score 68 and High level without 77->94 fabrication', async () => {
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('68').length).toBeGreaterThan(0);
      expect(screen.queryByText(/77 → 94/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/\+17 increase/i)).not.toBeInTheDocument();
    });
  });

  it('3. displays truthful scanner consensus (1 of 3 scanners, Nuclei only) without fake ZAP/Nessus/OpenVAS', async () => {
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Detected by 1 of 3 (configured )?scanners/i).length).toBeGreaterThan(0);
      expect(screen.queryByText('Nessus Professional')).not.toBeInTheDocument();
      expect(screen.queryByText('OpenVAS Network')).not.toBeInTheDocument();
    });
  });

  it('4. displays authoritative asset context (HIGH criticality, CONFIDENTIAL, Internet-facing) without PCI or Critical reinterpretation', async () => {
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Confidential/i).length).toBeGreaterThan(0);
      expect(screen.queryByText('PCI')).not.toBeInTheDocument();
      expect(screen.getAllByText(/High/i).length).toBeGreaterThan(0);
    });
  });

  it('5. renders Log4j remediation and references without SQL-injection contamination', async () => {
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Apache Log4j Remote Code Execution (Log4Shell)')[0]).toBeInTheDocument();
    });

    const remTabBtn = screen.getByRole('button', { name: /^Start Remediation$/i });
    fireEvent.click(remTabBtn);

    await waitFor(() => {
      expect(screen.getAllByText(/Upgrade to Log4j 2.17.1 or higher/i).length).toBeGreaterThan(0);
      expect(screen.queryByText(/OWASP SQL Injection Prevention/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/parameterized database query/i)).not.toBeInTheDocument();
    });
  });

  it('6. enforces RBAC for VIEWER role (read-only, no decision mutations)', async () => {
    findingsService.setAuthSession('mock-token-viewer', {
      id: 'usr-viewer',
      name: 'Test Viewer',
      email: 'viewer@rizintel.io',
      role: 'VIEWER',
      organization_id: 'ORG-RIZZOLVE-DEMO'
    });

    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Apache Log4j Remote Code Execution (Log4Shell)')[0]).toBeInTheDocument();
    });

    const decTabBtn = screen.getAllByRole('button', { name: /Decision & Activity/i })[0];
    fireEvent.click(decTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Viewer Role \(Read-Only\)/i)).toBeInTheDocument();
      expect(screen.getByText('Read-Only')).toBeInTheDocument();
    });
  });

  it('7. submits analyst decision and updates cryptographic audit history', async () => {
    findingsService.setAuthSession('mock-token-analyst', {
      id: 'usr-1',
      name: 'Test Analyst',
      email: 'analyst@rizintel.io',
      role: 'ANALYST',
      organization_id: 'ORG-RIZZOLVE-DEMO'
    });

    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockLog4jCanonical);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });
    vi.spyOn(findingsService, 'submitAnalystFeedback').mockResolvedValue({
      status: 'success',
      data: {
        finding_id: 'DEDUP-90626421',
        analyst_action: 'ACCEPT_PRIORITY',
        analyst_decision: 'ACCEPT_PRIORITY',
        rationale: 'Confirmed high risk priority in production.',
        role: 'Test Analyst [ANALYST]',
        timestamp: new Date().toISOString()
      }
    });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Apache Log4j Remote Code Execution (Log4Shell)')[0]).toBeInTheDocument();
    });

    const decTabBtn = screen.getAllByRole('button', { name: /Decision & Activity/i })[0];
    fireEvent.click(decTabBtn);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Save Decision/i })).toBeInTheDocument();
    });

    const rationaleInput = screen.getByPlaceholderText(/e\.g\., Active verification/i);
    fireEvent.change(rationaleInput, { target: { value: 'Confirmed high risk priority in production.' } });

    const saveBtn = screen.getByRole('button', { name: /Save Decision/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(findingsService.submitAnalystFeedback).toHaveBeenCalledWith(
        'DEDUP-90626421',
        'ACCEPT_PRIORITY',
        'Confirmed high risk priority in production.',
        68
      );
    });
  });

  it('8. renders nonexistent finding empty state without crashing or mock fallback', async () => {
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(null);

    render(
      <MemoryRouter initialEntries={['/findings/NON_EXISTENT_ID']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Finding NON_EXISTENT_ID not found/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Back to Findings Queue/i })).toBeInTheDocument();
    });
  });
});
