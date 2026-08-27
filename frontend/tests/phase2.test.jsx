import { describe, it, expect, beforeEach, vi } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

import ScanRunsPage from '../src/pages/ScanRunsPage';
import CommandCenter from '../src/pages/CommandCenter';
import * as workspaceService from '../src/services/workspaceService';
import * as ingestionService from '../src/services/ingestionService';
import * as findingsService from '../src/services/findingsService';

describe('Phase 2 Ingestion & Scan-Run Scoped Context', () => {
  const mockOrg = {
    organization_id: 'ORG-DEMO-001',
    display_name: 'RizIntel Demo Organization',
    created_at: '2026-08-24T00:00:00Z',
    is_active: true
  };

  const mockRun = {
    scan_run_id: 'SR-PHASE2-001',
    organization_id: 'ORG-DEMO-001',
    asset_id: 'ASSET-WEB-001',
    created_by_user_id: 'usr-lead-003',
    status: 'WAITING_FOR_INPUT',
    scanner_selections: ['ZAP', 'NUCLEI', 'WAPITI'],
    received_scanners: ['ZAP'],
    pending_scanners: ['NUCLEI', 'WAPITI'],
    data_origin: 'LIVE_SCAN',
    created_at: '2026-08-24T00:00:00Z',
    updated_at: '2026-08-24T00:00:00Z'
  };

  const mockSubmissions = [
    {
      submission_id: 'SUB-ZAP-001',
      scan_run_id: 'SR-PHASE2-001',
      organization_id: 'ORG-DEMO-001',
      asset_id: 'ASSET-WEB-001',
      scanner: 'ZAP',
      raw_finding_count: 5,
      processing_status: 'PARSED',
      received_at: '2026-08-24T00:05:00Z',
      storage_path: 'data/submissions/sub_zap.json'
    }
  ];

  const mockEvents = [
    {
      event_id: 'EVT-001',
      organization_id: 'ORG-DEMO-001',
      scan_run_id: 'SR-PHASE2-001',
      event_type: 'SCANNER_REPORT_RECEIVED',
      stage: 'INGESTION',
      status: 'SUCCESS',
      message: 'ZAP report stored (1500 bytes).',
      created_at: '2026-08-24T00:05:00Z'
    }
  ];

  const mockScopedResults = {
    scan_run_id: 'SR-PHASE2-001',
    asset_id: 'ASSET-WEB-001',
    completed_at: '2026-08-24T00:10:00Z',
    summary: { consensus_ratio: '3/3' },
    findings: [
      {
        finding_id: 'FND-SR1-001',
        cve_id: 'CVE-2026-1111',
        vulnerability_name: 'SQL Injection on Payments Gateway',
        severity: 'CRITICAL',
        risk_score: 95,
        risk_level: 'CRITICAL',
        vulnerability_type: 'SQL_INJECTION',
        asset: { asset_id: 'ASSET-WEB-001', host: 'payments.demo.corp' },
        scanner_consensus: { score: 1.0, detected_by_count: 2, total_scanners: 3 }
      }
    ]
  };

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(workspaceService, 'getMyOrganizations').mockResolvedValue([mockOrg]);
    vi.spyOn(workspaceService, 'getRegisteredAssets').mockResolvedValue([]);
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue([mockRun]);
    vi.spyOn(ingestionService, 'getScanRunSubmissions').mockResolvedValue(mockSubmissions);
    vi.spyOn(ingestionService, 'getScanRunEvents').mockResolvedValue(mockEvents);
    vi.spyOn(findingsService, 'getScanRunFindings').mockResolvedValue(mockScopedResults);
  });

  it('renders Scan Runs list with consensus tracking', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    render(
      <MemoryRouter initialEntries={['/scan-runs']}>
        <Routes>
          <Route path="/scan-runs" element={<ScanRunsPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('SR-PHASE2-001')).toBeDefined();
    });

    expect(screen.getByText('1 / 3')).toBeDefined();
  });

  it('opens detailed scan run modal showing Scanner Cards & Real Stage Events', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    render(
      <MemoryRouter initialEntries={['/scan-runs']}>
        <Routes>
          <Route path="/scan-runs" element={<ScanRunsPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Manage Run').length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getAllByText('Manage Run')[0]);

    await waitFor(() => {
      expect(screen.getByText('Multi-Scanner Ingestion Status')).toBeDefined();
    });

    expect(screen.getAllByText('ZAP').length).toBeGreaterThan(0);
    expect(screen.getAllByText('NUCLEI').length).toBeGreaterThan(0);
    expect(screen.getAllByText('WAPITI').length).toBeGreaterThan(0);
    expect(screen.getByText('[SCANNER_REPORT_RECEIVED]')).toBeDefined();
  });

  it('loads scan-run scoped findings in Command Center when ?scan_run_id and ?org_id are present', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    render(
      <MemoryRouter initialEntries={['/command-center?scan_run_id=SR-PHASE2-001&org_id=ORG-DEMO-001']}>
        <Routes>
          <Route path="/command-center" element={<CommandCenter />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Viewing results for Scan Run/i)).toBeDefined();
    });
  });
});
