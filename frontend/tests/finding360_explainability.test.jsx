import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import Finding360 from '../src/pages/Finding360';
import * as findingsService from '../src/services/findingsService';

const mockFindingWithM6 = {
  finding_id: 'DEDUP-90626421',
  vulnerability_name: 'Apache Log4j Remote Code Execution (Log4Shell)',
  vulnerability_type: 'RCE',
  cve_id: 'CVE-2021-44228',
  asset_id: 'AST-ERP-001',
  asset_name: 'ERP-PROD-APP01',
  asset_criticality: 'HIGH',
  internet_exposure: true,
  risk_score: 68,
  risk_level: 'HIGH',
  confidence_classification: 'High Confidence',
  recommended_action: 'Upgrade org.apache.logging.log4j:log4j-core to version 2.17.1 or newer.',
  created_at: '2026-08-27T12:00:00Z',
  workflow: {
    status: 'OPEN',
    priority: 'MEDIUM',
    sla_hours: 168,
    ticket_id: 'TICK-9062'
  },
  detail: {
    asset_context: {
      asset_name: 'ERP-PROD-APP01',
      environment: 'production',
      criticality: 'HIGH',
      internet_facing: true,
      data_sensitivity: 'CONFIDENTIAL',
      owner: 'SecOps Team'
    },
    threat_intelligence: {
      cve_id: 'CVE-2021-44228',
      kev_listed: true,
      epss_score: 0.91,
      cvss_score: 9.1,
      exploit_available: false
    },
    finding_confidence: {
      score: 0.85,
      classification: 'HIGH_CONFIDENCE'
    },
    risk_assessment: {
      score_breakdown: {
        cvss_contribution: 20,
        epss_contribution: 14,
        kev_contribution: 15,
        exploit_contribution: 0,
        asset_criticality_contribution: 8,
        exposure_contribution: 10,
        scanner_confidence_contribution: 8
      }
    },
    scanner_consensus: {
      detected_by_count: 1,
      total_scanners: 3,
      scanner_names: ['Nuclei']
    },
    provenance: {
      source_findings: [
        {
          finding_id: 'NUC-001',
          scanner: 'Nuclei',
          severity: 'CRITICAL',
          timestamp: '2026-08-27T11:55:00Z'
        }
      ]
    },
    explanation: {
      technical: 'Remote Code Execution vulnerability in Log4j core on asset ERP-PROD-APP01. Base CVSS severity is 9.1 and EPSS probability is in the 91st percentile. This system is internet-facing with High business criticality.',
      management: 'Critical Log4Shell exposure on production ERP application. Confirmed active in CISA KEV catalog. Remediation required within SLA window.',
      top_risk_drivers: ['CRITICAL_ASSET', 'KEV_LISTED', 'INTERNET_FACING'],
      generated_at: '2026-08-27T12:05:00Z',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
        'https://logging.apache.org/log4j/2.x/security.html'
      ]
    }
  }
};

describe('Finding360 M6 Explainable AI Production Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    findingsService.setAuthSession('mock-token-analyst', {
      id: 'usr-1',
      name: 'Security Lead',
      email: 'lead@rizintel.io',
      role: 'SECURITY_LEAD',
      organization_id: 'ORG-RIZZOLVE-DEMO'
    });
    vi.spyOn(findingsService, 'getFindingById').mockResolvedValue(mockFindingWithM6);
    vi.spyOn(findingsService, 'fetchAuditTrail').mockResolvedValue([
      {
        id: 1,
        action: 'ACCEPT_PRIORITY',
        actor: 'Security Lead',
        created_at: '2026-08-27T12:10:00Z'
      }
    ]);
    vi.spyOn(findingsService, 'verifyAuditTrail').mockResolvedValue({ valid: true });
  });

  it('1. includes Explainability as the dedicated 3rd tab in the tab bar', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      const tabButtons = screen.getAllByRole('tab');
      expect(tabButtons.length).toBeGreaterThanOrEqual(6);
      expect(tabButtons[0]).toHaveTextContent('Overview');
      expect(tabButtons[1]).toHaveTextContent('Evidence');
      expect(tabButtons[2]).toHaveTextContent('Explainability');
      expect(tabButtons[3]).toHaveTextContent('Journey');
      expect(tabButtons[4]).toHaveTextContent('Remediation');
      expect(tabButtons[5]).toHaveTextContent('Decision & Activity');
    });
  });

  it('2. deep-links to Explainability tab via ?tab=explainability URL parameter', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(document.getElementById('tabpanel-explainability')).toBeInTheDocument();
      expect(screen.getByText('RizIntel Explainability')).toBeInTheDocument();
      expect(screen.getByText('Understand the verified signals behind RizIntel’s risk decision.')).toBeInTheDocument();
    });
  });

  it('3. renders Overview "Why this risk?" preview card with management summary and driver chips', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Why this risk?')).toBeInTheDocument();
      expect(screen.getByText(/Critical Log4Shell exposure on production ERP application/i)).toBeInTheDocument();
      expect(screen.getByText('High Asset Criticality')).toBeInTheDocument();
      expect(screen.getByText('CISA KEV Listed')).toBeInTheDocument();
      expect(screen.getByText('Internet-Facing Asset')).toBeInTheDocument();
      expect(screen.getByText('View Full Explanation →')).toBeInTheDocument();
    });
  });

  it('4. clicking "View Full Explanation →" on Overview navigates to Explainability tab', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('View Full Explanation →')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('View Full Explanation →'));

    await waitFor(() => {
      expect(document.getElementById('tabpanel-explainability')).toBeInTheDocument();
      expect(screen.getByText('Why RizIntel assigned this risk')).toBeInTheDocument();
    });
  });

  it('5. Section A displays Decision Summary with Contextual Risk 68/100, Confidence, Analyst Validation, and Timestamp', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Why RizIntel assigned this risk')).toBeInTheDocument();
      expect(screen.getByText('Based on the evidence available when this finding was analyzed')).toBeInTheDocument();
      expect(screen.getByText('Generated Timestamp')).toBeInTheDocument();
      expect(screen.getAllByText('68').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('/ 100').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Confirmed/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('6. Section B & D supports toggling between Analyst View and Executive View purely in React state', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Security Analyst Technical Narrative')).toBeInTheDocument();
      expect(screen.getByText(/Remote Code Execution vulnerability in Log4j/i)).toBeInTheDocument();
    });

    // Toggle to Executive View
    const execBtn = screen.getByRole('tab', { name: /executive view/i });
    fireEvent.click(execBtn);

    await waitFor(() => {
      expect(screen.getByText('Executive Management Summary')).toBeInTheDocument();
      expect(screen.getByText(/Critical Log4Shell exposure on production ERP application/i)).toBeInTheDocument();
    });
  });

  it('7. Section C renders semantically validated driver cards with "High Asset Criticality" for HIGH asset', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      // Must NOT display "Critical Asset" for an asset whose criticality is HIGH
      expect(screen.getAllByText('High Asset Criticality').length).toBeGreaterThanOrEqual(1);
      expect(screen.queryByText('Critical Asset')).not.toBeInTheDocument();
      expect(screen.getByText('CISA KEV Listed')).toBeInTheDocument();
      expect(screen.getByText('Internet-Facing Asset')).toBeInTheDocument();
      expect(screen.getByText('+8 / 10 pts')).toBeInTheDocument();
      expect(screen.getByText('+15 / 15 pts')).toBeInTheDocument();
      expect(screen.getByText('+10 / 10 pts')).toBeInTheDocument();
    });
  });

  it('8. Section E & F renders Evidence Basis and Data Considered completeness lists', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Evidence used for this explanation')).toBeInTheDocument();
      expect(screen.getByText('Data considered')).toBeInTheDocument();
      expect(screen.getByText(/Available Signals/i)).toBeInTheDocument();
      expect(screen.getByText(/Signals Not Available/i)).toBeInTheDocument();
      expect(screen.getAllByText('Public exploit information not available').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('9. Section G & H renders Recommended Next Step with M7 priority/SLA governance and References', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Recommended next step')).toBeInTheDocument();
      expect(screen.getByText('M7 Remediation Engine')).toBeInTheDocument();
      expect(screen.getByText(/168 hours \(7 days\)/i)).toBeInTheDocument();
      expect(screen.getByText('Authoritative References')).toBeInTheDocument();
      expect(screen.getByText('nvd.nist.gov Advisory')).toBeInTheDocument();
      expect(screen.getByText('logging.apache.org Advisory')).toBeInTheDocument();
    });
  });

  it('10. Copy Explanation button works and displays confirmation feedback', async () => {
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined),
      },
    });

    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=explainability']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /copy explanation/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /copy explanation/i }));

    expect(navigator.clipboard.writeText).toHaveBeenCalled();
    await waitFor(() => {
      expect(screen.getByText('Copied')).toBeInTheDocument();
    });
  });

  it('11. Journey tab reflects the Explainability lifecycle stage', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/DEDUP-90626421?tab=journey']}>
        <Routes>
          <Route path="/findings/:id" element={<Finding360 />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Finding Lifecycle Journey')).toBeInTheDocument();
      expect(screen.getAllByText('Explainability').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/3 Drivers · Generated/i)).toBeInTheDocument();
    });
  });
});
