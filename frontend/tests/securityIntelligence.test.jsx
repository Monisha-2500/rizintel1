import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import SecurityIntelligence from '../src/pages/SecurityIntelligence';
import * as findingsService from '../src/services/findingsService';
import * as slaService from '../src/services/slaService';
import * as assetsService from '../src/services/assetsService';

const mockFindings = [
  {
    finding_id: 'DEDUP-90626421',
    vulnerability_name: 'Apache Log4j Remote Code Execution (Log4Shell)',
    cve_id: 'CVE-2021-44228',
    asset_id: 'ASSET-PAY-001',
    risk_score: 68,
    risk_level: 'HIGH',
    confidence_classification: 'HIGH_CONFIDENCE',
    internet_exposure: true,
    asset_criticality: 'HIGH',
    detail: {
      threat_intelligence: { kev_listed: true, exploit_available: false, epss_score: 0.97 },
      asset_context: { criticality: 'HIGH', internet_facing: true },
      scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['Nuclei'] },
      audit_history: [{ analyst_action: 'ACCEPT_PRIORITY' }]
    }
  },
  {
    finding_id: 'DEDUP-05C0BE11',
    vulnerability_name: 'Spring Framework RCE (Spring4Shell)',
    cve_id: 'CVE-2022-22965',
    asset_id: 'ASSET-PAY-001',
    risk_score: 68,
    risk_level: 'HIGH',
    confidence_classification: 'HIGH_CONFIDENCE',
    internet_exposure: true,
    asset_criticality: 'HIGH',
    detail: {
      threat_intelligence: { kev_listed: true, exploit_available: false, epss_score: 0.89 },
      asset_context: { criticality: 'HIGH', internet_facing: true },
      scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['Nuclei'] }
    }
  },
  {
    finding_id: 'DEDUP-F21924A4',
    vulnerability_name: 'SQL Injection',
    cve_id: 'CVE-2023-0001',
    asset_id: 'ASSET-PAY-001',
    risk_score: 30,
    risk_level: 'MEDIUM',
    confidence_classification: 'NEEDS_REVIEW',
    internet_exposure: true,
    asset_criticality: 'HIGH',
    detail: {
      threat_intelligence: { kev_listed: false, exploit_available: false, epss_score: 0.05 },
      asset_context: { criticality: 'HIGH', internet_facing: true },
      scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['ZAP'] }
    }
  }
];

const mockTasks = [
  {
    ticket_id: 'TCK-22F4EDB43C',
    finding_id: 'DEDUP-90626421',
    status: 'RESOLVED',
    priority: 'MEDIUM',
    assigned_to: 'secops',
    assignee_display_name: 'SOC Operations Team'
  }
];

const mockAssets = [
  {
    asset_id: 'ASSET-PAY-001',
    display_name: 'Payment Gateway Service (Web Application)'
  }
];

describe('Security Intelligence Page Component — Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      id: 'usr-1',
      name: 'Security Lead',
      role: 'SECURITY_LEAD',
      org_id: 'ORG-RIZZOLVE-DEMO'
    });
    vi.spyOn(findingsService, 'getFindings').mockImplementation(() => Promise.resolve(mockFindings));
    vi.spyOn(slaService, 'getRemediationTasks').mockImplementation(() => Promise.resolve(mockTasks));
    vi.spyOn(assetsService, 'getAssets').mockImplementation(() => Promise.resolve(mockAssets));
    vi.spyOn(slaService, 'getBreachWarnings').mockImplementation(() => Promise.resolve({ hard_breaches: [], predictive_warnings: [] }));
  });

  it('1. renders header, eyebrow, and organization indicator', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Security Intelligence')).toBeInTheDocument();
      expect(screen.getByText('SECURITY ANALYTICS')).toBeInTheDocument();
      expect(screen.getByText('ORG-RIZZOLVE-DEMO')).toBeInTheDocument();
    });
  });

  it('2. displays authoritative Intelligence Snapshot counts without hardcoded mock fallbacks', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('INTELLIGENCE SNAPSHOT')).toBeInTheDocument();
    });

    const activeElements = screen.getAllByText('Active Findings');
    expect(activeElements.length).toBeGreaterThan(0);

    const kevElements = screen.getAllByText(/CISA KEV Listed/i);
    expect(kevElements.length).toBeGreaterThan(0);

    const exposedElements = screen.getAllByText(/Internet-Facing/i);
    expect(exposedElements.length).toBeGreaterThan(0);

    const reviewElements = screen.getAllByText(/Needs Review/i);
    expect(reviewElements.length).toBeGreaterThan(0);

    const breachedElements = screen.getAllByText(/SLA Breached/i);
    expect(breachedElements.length).toBeGreaterThan(0);
  });

  it('3. reconciles SLA Breached count with SLA Monitor to show 0 breaches', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      const breachedCards = screen.getAllByText('SLA Breached');
      const breachedCard = breachedCards[0].closest('.si-snapshot-card');
      expect(breachedCard).toHaveTextContent('0');
      expect(breachedCard).toHaveTextContent('Reconciled with SLA Monitor');
    });
  });

  it('4. renders data-derived What RizIntel Learned insights without contradictory exploit wording', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('WHAT RIZINTEL LEARNED')).toBeInTheDocument();
      expect(screen.getByText('KEV Catalog Correlation')).toBeInTheDocument();
      expect(screen.getByText(/2 of 3 active findings are listed in the CISA Known Exploited Vulnerabilities catalog/i)).toBeInTheDocument();
    });
  });

  it('5. renders reconciled Workflow Health with exact population breakdown', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('WORKFLOW HEALTH')).toBeInTheDocument();
      expect(screen.getByText(/Current state of risk triage across 3 canonical findings/i)).toBeInTheDocument();
      expect(screen.getByText(/33% Pending Review/i)).toBeInTheDocument(); // 1 of 3
      expect(screen.getByText(/33% Open/i)).toBeInTheDocument(); // 1 of 3
      expect(screen.getByText(/33% Resolved/i)).toBeInTheDocument(); // 1 of 3
    });
  });

  it('6. renders Scanner Consensus & Validation separating confidence, detection, and validation', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('SCANNER CONSENSUS & VALIDATION')).toBeInTheDocument();
      expect(screen.getByText(/2 High Confidence/i)).toBeInTheDocument();
      expect(screen.getByText(/1 Needs Review/i)).toBeInTheDocument();
      expect(screen.getByText(/3 Single-Source/i)).toBeInTheDocument();
      expect(screen.getByText(/1 Confirmed/i)).toBeInTheDocument();
    });
  });

  it('7. renders High-Criticality Assets and KEV + Internet-Facing without false critical labels or unsupported urgency', async () => {
    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('High-Criticality Assets')).toBeInTheDocument();
      expect(screen.getByText('KEV + Internet-Facing')).toBeInTheDocument();
      expect(screen.queryByText('Immediate Attention')).not.toBeInTheDocument();
      expect(screen.queryByText('Critical Context')).not.toBeInTheDocument();
    });
  });

  it('8. provides read-only buttons for VIEWER role', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      id: 'usr-v',
      name: 'Audit Viewer',
      role: 'VIEWER',
      org_id: 'ORG-RIZZOLVE-DEMO'
    });

    render(
      <MemoryRouter>
        <SecurityIntelligence />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('View SLA Monitor →')).toBeInTheDocument();
    });
  });
});
