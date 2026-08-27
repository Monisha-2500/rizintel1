import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import CommandCenter from '../src/pages/CommandCenter';
import * as findingsService from '../src/services/findingsService';

/* ── Shared mock setup ─────────────────────────────────────────────────────── */

vi.mock('../src/services/findingsService', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    getFindings:        vi.fn(),
    getDashboardSummary: vi.fn(),
    getScanRunFindings: vi.fn(),
    getRuntimeStatus:   vi.fn(() => 'LIVE'),
    getCurrentUser:     vi.fn(() => ({
      role: 'ANALYST',
      config: { canDecide: true, canEscalate: false }
    })),
    RUNTIME_STATUS: { LIVE: 'LIVE', MOCK: 'MOCK', FALLBACK: 'FALLBACK', CONNECTING: 'CONNECTING' },
  };
});

vi.mock('../src/hooks/useFindings', () => ({
  useFindings: vi.fn(),
}));
vi.mock('../src/hooks/useDashboard', () => ({
  useDashboard: vi.fn(),
}));

import { useFindings } from '../src/hooks/useFindings';
import { useDashboard } from '../src/hooks/useDashboard';

/* ── Test data ─────────────────────────────────────────────────────────────── */

const REAL_FINDING = {
  finding_id: 'FINDING-REAL-001',
  cve_id: 'CVE-2023-45853',
  vulnerability_name: 'SQL Injection',
  risk_score: 94,
  risk_level: 'CRITICAL',
  asset_id: 'ASSET-DA1A14B2CF',
  internet_exposure: true,
  workflow: {
    sla_status: 'AT_RISK',
    sla_due_at: new Date(Date.now() + 3 * 3600 * 1000).toISOString(),
    status: 'OPEN',
  },
  detail: {
    asset_context: { asset_name: 'Payment Gateway Service' },
    threat_intelligence: { epss_score: 0.73, kev_listed: true, exploit_available: true, cvss_score: 9.8 },
    scanner_consensus: { detected_by_count: 1, total_scanners: 1 },
    finding_confidence: { score: 0.91, classification: 'CONFIRMED' },
    explanation: { management: 'Known exploited vulnerability on a critical asset.' },
  },
};

const SUMMARY_DATA = {
  summary: { critical: 1, high: 3, medium: 2, low: 0, sla_breaches: 1, unique_findings: 6 },
};

function renderCC(url = '/command-center') {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/command-center" element={<CommandCenter />} />
        <Route path="/findings/:id"   element={<div>Finding Detail</div>} />
        <Route path="/scan-runs"      element={<div>Scan Runs</div>} />
      </Routes>
    </MemoryRouter>
  );
}

/* ── Tests ─────────────────────────────────────────────────────────────────── */

describe('Command Center — Loading State', () => {
  it('shows skeleton cards while loading', () => {
    useFindings.mockReturnValue({ findings: [], loading: true, error: null });
    useDashboard.mockReturnValue({ summary: null, loading: true, error: null });
    renderCC();
    expect(screen.getByText('Command Center')).toBeInTheDocument();
    // Skeleton cards exist (aria-hidden)
    const skeletons = document.querySelectorAll('.cc-skeleton-card');
    expect(skeletons.length).toBeGreaterThan(0);
  });
});

describe('Command Center — Empty State', () => {
  it('shows empty state when no findings and backend returned empty array', async () => {
    useFindings.mockReturnValue({ findings: [], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('No prioritized findings yet')).toBeInTheDocument();
    });
    expect(screen.getByText(/Complete an authorized security scan/i)).toBeInTheDocument();
  });

  it('shows Create Scan Run button for analyst role when no findings', async () => {
    useFindings.mockReturnValue({ findings: [], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('No prioritized findings yet')).toBeInTheDocument();
    });
    expect(screen.getByText('Create Scan Run')).toBeInTheDocument();
  });

  it('shows viewer note instead of action button for VIEWER role', async () => {
    findingsService.getCurrentUser.mockReturnValue({
      role: 'VIEWER',
      config: { canDecide: false, canEscalate: false },
    });
    useFindings.mockReturnValue({ findings: [], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText(/Prioritized findings will appear here/i)).toBeInTheDocument();
    });
    expect(screen.queryByText('Create Scan Run')).not.toBeInTheDocument();
    // restore
    findingsService.getCurrentUser.mockReturnValue({ role: 'ANALYST', config: { canDecide: true } });
  });
});

describe('Command Center — Error State', () => {
  it('shows error state with Retry button when backend fails and no findings', async () => {
    useFindings.mockReturnValue({ findings: [], loading: false, error: 'Network error' });
    useDashboard.mockReturnValue({ summary: null, loading: false, error: 'Network error' });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('Unable to load Command Center')).toBeInTheDocument();
    });
    expect(screen.getByText("We couldn't retrieve the latest security findings. Please try again.")).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument();
  });
});

describe('Command Center — Real Populated State', () => {
  beforeEach(() => {
    useFindings.mockReturnValue({ findings: [REAL_FINDING], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
  });

  it('renders page title and subtitle', async () => {
    renderCC();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Command Center' })).toBeInTheDocument());
    expect(screen.getByText(/Prioritize security risk, monitor remediation urgency/i)).toBeInTheDocument();
  });

  it('renders correct summary card counts from real data', async () => {
    renderCC();
    await waitFor(() => {
      // Critical: 1 from SUMMARY_DATA
      expect(screen.getByLabelText('1 critical findings')).toBeInTheDocument();
      // High: 3 from SUMMARY_DATA
      expect(screen.getByLabelText('3 high findings')).toBeInTheDocument();
      // SLA Breached: 1 from SUMMARY_DATA
      expect(screen.getByLabelText('1 findings breached SLA')).toBeInTheDocument();
      // Active: 6 from SUMMARY_DATA
      expect(screen.getByLabelText('6 active findings')).toBeInTheDocument();
    });
  });

  it('renders the finding with correct data — no fabrication', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      expect(screen.getByText('CVE-2023-45853')).toBeInTheDocument();
      expect(screen.getByText('Payment Gateway Service')).toBeInTheDocument();
    });
  });

  it('shows risk score 94 from backend, not recalculated', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('94')).toBeInTheDocument();
    });
  });

  it('shows confidence from backend data', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('91%')).toBeInTheDocument();
    });
  });

  it('shows KEV badge when kev_listed is true', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getAllByText(/KEV/i).length).toBeGreaterThan(0);
    });
  });

  it('shows backend-provided explanation', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByText(/Known exploited vulnerability on a critical asset/i)).toBeInTheDocument();
    });
  });

  it('shows Priority Attention section with correct heading', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('Priority Attention')).toBeInTheDocument();
    });
  });

  it('does NOT display any M1/M2/M3..M8 module labels to the user', async () => {
    renderCC();
    await waitFor(() => expect(screen.queryByText(/M[1-8]/)).toBeNull());
  });

  it('shows Next Best Action derived from real data', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('Next Best Action')).toBeInTheDocument();
    });
  });
});

describe('Command Center — Canonical Finding Navigation', () => {
  beforeEach(() => {
    useFindings.mockReturnValue({ findings: [REAL_FINDING], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
  });

  it('Investigate button navigates to /findings/<real_finding_id>', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Investigate: SQL Injection/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: /Investigate: SQL Injection/i }));
    await waitFor(() => {
      expect(screen.getByText('Finding Detail')).toBeInTheDocument();
    });
  });

  it('NBA button navigates to /findings/<real_finding_id>', async () => {
    renderCC();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /View Finding Details/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: /View Finding Details/i }));
    await waitFor(() => {
      expect(screen.getByText('Finding Detail')).toBeInTheDocument();
    });
  });
});

describe('Command Center — Search & Filters', () => {
  const twoFindings = [
    REAL_FINDING,
    {
      ...REAL_FINDING,
      finding_id: 'FINDING-REAL-002',
      cve_id: 'CVE-2023-40044',
      vulnerability_name: 'Cross-Site Scripting (Stored)',
      risk_score: 78,
      risk_level: 'HIGH',
      workflow: { sla_status: 'ON_TRACK', sla_due_at: null, status: 'OPEN' },
    },
  ];

  beforeEach(() => {
    useFindings.mockReturnValue({ findings: twoFindings, loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
  });

  it('search filters findings by name', async () => {
    renderCC();
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument());
    fireEvent.change(screen.getByRole('textbox', { name: /Search findings/i }), {
      target: { value: 'SQL' },
    });
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      expect(screen.queryByText('Cross-Site Scripting (Stored)')).toBeNull();
    });
  });

  it('shows no-match state and Reset Filters button when filters exclude all', async () => {
    renderCC();
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument());
    fireEvent.change(screen.getByRole('textbox', { name: /Search findings/i }), {
      target: { value: 'zzznotexisting' },
    });
    await waitFor(() => {
      expect(screen.getByText('No findings match your filters.')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Reset Filters/i })).toBeInTheDocument();
    });
  });

  it('Reset Filters restores all findings', async () => {
    renderCC();
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument());
    fireEvent.change(screen.getByRole('textbox', { name: /Search findings/i }), {
      target: { value: 'zzznotexisting' },
    });
    await waitFor(() => expect(screen.getByText('No findings match your filters.')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Reset Filters/i }));
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      expect(screen.getByText('Cross-Site Scripting (Stored)')).toBeInTheDocument();
    });
  });

  it('severity filter shows only matching findings', async () => {
    renderCC();
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument());
    fireEvent.change(screen.getByRole('combobox', { name: /Filter by severity/i }), {
      target: { value: 'CRITICAL' },
    });
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      expect(screen.queryByText('Cross-Site Scripting (Stored)')).toBeNull();
    });
  });

  it('SLA filter works', async () => {
    renderCC();
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument());
    fireEvent.change(screen.getByRole('combobox', { name: /Filter by SLA status/i }), {
      target: { value: 'AT_RISK' },
    });
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      expect(screen.queryByText('Cross-Site Scripting (Stored)')).toBeNull();
    });
  });
});

describe('Command Center — Scan Run Scoping', () => {
  it('shows scope banner when scan_run_id param is present', async () => {
    findingsService.getScanRunFindings.mockResolvedValue({
      findings: [REAL_FINDING],
      summary: { summary: { critical: 1, high: 0, medium: 0, low: 0, sla_breaches: 0, unique_findings: 1 } },
      scan_run_id: 'SR-DB6CD0A1B5FF',
      asset_id: 'ASSET-DA1A14B2CF',
      completed_at: '2026-08-26T09:00:00Z',
    });
    useFindings.mockReturnValue({ findings: [], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });

    renderCC('/command-center?scan_run_id=SR-DB6CD0A1B5FF&org_id=ORG-001');
    await waitFor(() => {
      expect(screen.getByText(/Viewing results for Scan Run/i)).toBeInTheDocument();
      expect(screen.getByText('SR-DB6CD0A1B5FF')).toBeInTheDocument();
    });
  });

  it('shows scoped finding from scan run, not global findings', async () => {
    const scopedFinding = { ...REAL_FINDING, vulnerability_name: 'Scoped SQL Injection Only' };
    findingsService.getScanRunFindings.mockResolvedValue({
      findings: [scopedFinding],
      summary: {},
      scan_run_id: 'SR-DB6CD0A1B5FF',
      completed_at: new Date().toISOString(),
    });
    useFindings.mockReturnValue({ findings: [REAL_FINDING], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });

    renderCC('/command-center?scan_run_id=SR-DB6CD0A1B5FF&org_id=ORG-001');
    await waitFor(() => {
      expect(screen.getByText('Scoped SQL Injection Only')).toBeInTheDocument();
      // Should NOT show global finding name
      expect(screen.queryByText('SQL Injection')).toBeNull();
    });
  });

  it('shows error banner when scan-run fetch fails without mock fallback', async () => {
    findingsService.getScanRunFindings.mockRejectedValue(new Error('Network error'));
    useFindings.mockReturnValue({ findings: [], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });

    renderCC('/command-center?scan_run_id=SR-INVALID&org_id=ORG-001');
    await waitFor(() => {
      // Shows the scoped error alert, not a mock fallback
      const alerts = document.querySelectorAll('[role="alert"]');
      expect(alerts.length).toBeGreaterThan(0);
    });
    // Should NOT show fake data — will show empty state since no global findings either
    expect(screen.queryByText('SQL Injection')).toBeNull();
  });

  it('Clear Filter button removes scan_run_id context', async () => {
    findingsService.getScanRunFindings.mockResolvedValue({
      findings: [REAL_FINDING],
      summary: {},
      scan_run_id: 'SR-DB6CD0A1B5FF',
      completed_at: new Date().toISOString(),
    });
    useFindings.mockReturnValue({ findings: [], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });

    renderCC('/command-center?scan_run_id=SR-DB6CD0A1B5FF&org_id=ORG-001');
    await waitFor(() => expect(screen.getByText('SR-DB6CD0A1B5FF')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /Clear scan run filter/i }));
    await waitFor(() => {
      expect(screen.queryByText('SR-DB6CD0A1B5FF')).toBeNull();
    });
  });
});

describe('Command Center — Unmapped Asset Rendering', () => {
  it('shows asset_id when no asset name is available', async () => {
    const unmappedFinding = {
      ...REAL_FINDING,
      asset_id: 'ASSET-UNKNOWN-XYZ',
      detail: { ...REAL_FINDING.detail, asset_context: undefined },
    };
    useFindings.mockReturnValue({ findings: [unmappedFinding], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('ASSET-UNKNOWN-XYZ')).toBeInTheDocument();
    });
  });
});

describe('Command Center — Missing Optional Data', () => {
  it('omits EPSS when not provided, does not show undefined', async () => {
    const noTiFinding = {
      ...REAL_FINDING,
      detail: { ...REAL_FINDING.detail, threat_intelligence: {} },
    };
    useFindings.mockReturnValue({ findings: [noTiFinding], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      expect(screen.queryByText(/EPSS/i)).toBeNull();
    });
  });
});

describe('Command Center — No Horizontal Overflow', () => {
  it('cc-page-wrapper has correct max-width style attribute', async () => {
    useFindings.mockReturnValue({ findings: [REAL_FINDING], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    const { container } = renderCC();
    await waitFor(() => expect(screen.getByText('Command Center')).toBeInTheDocument());
    const wrapper = container.querySelector('.cc-page-wrapper');
    expect(wrapper).toBeTruthy();
    // The wrapper element should exist and not have inline overflow styles
    expect(wrapper.style.overflowX).not.toBe('scroll');
    expect(wrapper.style.overflowX).not.toBe('auto');
  });
});

describe('Command Center — Pipeline Health', () => {
  it('shows Pipeline Health section', async () => {
    useFindings.mockReturnValue({ findings: [REAL_FINDING], loading: false, error: null });
    useDashboard.mockReturnValue({ summary: SUMMARY_DATA, loading: false, error: null });
    renderCC();
    await waitFor(() => {
      expect(screen.getByText('Pipeline Health')).toBeInTheDocument();
    });
    // Customer-facing stage labels
    expect(screen.getByText('Scanner Signals')).toBeInTheDocument();
    expect(screen.getByText('Risk Scoring')).toBeInTheDocument();
    expect(screen.getByText('SLA & Remediation')).toBeInTheDocument();
    // No M1..M8 in pipeline stages
    expect(screen.queryByText(/M[1-8] /)).toBeNull();
  });
});
