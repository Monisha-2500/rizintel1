import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ScanRunsPage from '../src/pages/ScanRunsPage';
import * as workspaceService from '../src/services/workspaceService';
import * as ingestionService from '../src/services/ingestionService';
import * as findingsService from '../src/services/findingsService';
import * as streamService from '../src/services/streamService';

describe('Phase 3 Real-Time Scan Operations & Live Pipeline Visualization', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    vi.spyOn(workspaceService, 'getMyOrganizations').mockResolvedValue([
      { organization_id: 'ORG-DEMO-001', display_name: 'Demo Corp' }
    ]);

    vi.spyOn(workspaceService, 'getRegisteredAssets').mockResolvedValue([
      { asset_id: 'ASSET-001', display_name: 'Target Service', authorization_status: 'AUTHORIZED' }
    ]);

    vi.spyOn(streamService, 'issueStreamToken').mockResolvedValue({
      stream_token: 'mock_stream_token_123'
    });
  });

  it('21. scanner card reacts to received event in real-time', async () => {
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue([
      {
        scan_run_id: 'SR-LIVE-001',
        organization_id: 'ORG-DEMO-001',
        asset_id: 'ASSET-001',
        scanner_selections: ['ZAP', 'NUCLEI'],
        status: 'WAITING_FOR_INPUT',
        created_at: new Date().toISOString()
      }
    ]);

    vi.spyOn(ingestionService, 'getScanRunSubmissions').mockResolvedValue([
      {
        submission_id: 'SUB-001',
        scanner: 'ZAP',
        processing_status: 'PARSED',
        raw_finding_count: 18,
        received_at: new Date().toISOString()
      }
    ]);

    vi.spyOn(ingestionService, 'getScanRunEvents').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunResults').mockResolvedValue(null);

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

    expect(screen.getByText('RECEIVED')).toBeDefined();
    expect(screen.getByText('18')).toBeDefined();
  });

  it('22. pipeline stage reacts to real stage events', async () => {
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue([
      {
        scan_run_id: 'SR-LIVE-002',
        organization_id: 'ORG-DEMO-001',
        asset_id: 'ASSET-001',
        scanner_selections: ['ZAP'],
        status: 'PROCESSING',
        created_at: new Date().toISOString()
      }
    ]);

    vi.spyOn(ingestionService, 'getScanRunSubmissions').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunEvents').mockResolvedValue([
      {
        event_id: 'EVT-STAGE-001',
        event_type: 'NORMALIZATION_COMPLETED',
        stage: 'M1',
        status: 'SUCCESS',
        message: 'Normalized 18 raw findings cleanly.',
        created_at: new Date().toISOString()
      }
    ]);

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
      expect(screen.getByText('[NORMALIZATION_COMPLETED]')).toBeDefined();
    });
  });

  it('23. live counts grid displays pipeline metrics', async () => {
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue([
      {
        scan_run_id: 'SR-LIVE-033',
        organization_id: 'ORG-DEMO-001',
        asset_id: 'ASSET-001',
        scanner_selections: ['ZAP'],
        status: 'COMPLETED',
        created_at: new Date().toISOString()
      }
    ]);

    vi.spyOn(ingestionService, 'getScanRunSubmissions').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunEvents').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunResults').mockResolvedValue({
      result_id: 'RES-001',
      summary: {
        pipeline_summary: {
          summary: {
            raw_findings: 55,
            unique_findings: 21,
            duplicates_correlated: 34,
            actionable_findings: 4,
            pending_review_findings: 17,
            likely_noise_findings: 0
          }
        }
      }
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
      expect(screen.getByText('Live Pipeline Counts')).toBeDefined();
    });

    expect(screen.getAllByText('55').length).toBeGreaterThan(0);
    expect(screen.getAllByText('21').length).toBeGreaterThan(0);
  });

  it('24. completed run enables Open Command Center transition button', async () => {
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue([
      {
        scan_run_id: 'SR-DONE-099',
        organization_id: 'ORG-DEMO-001',
        asset_id: 'ASSET-001',
        scanner_selections: ['ZAP'],
        status: 'COMPLETED',
        created_at: new Date().toISOString()
      }
    ]);

    vi.spyOn(ingestionService, 'getScanRunSubmissions').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunEvents').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunResults').mockResolvedValue({
      result_id: 'RES-099',
      summary: {}
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
      expect(screen.getByText('Open Command Center Results')).toBeDefined();
    });
  });

  it('25. failed run renders FAILED badge without completed state', async () => {
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue([
      {
        scan_run_id: 'SR-FAIL-999',
        organization_id: 'ORG-DEMO-001',
        asset_id: 'ASSET-001',
        scanner_selections: ['ZAP'],
        status: 'FAILED',
        created_at: new Date().toISOString()
      }
    ]);

    vi.spyOn(ingestionService, 'getScanRunSubmissions').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunEvents').mockResolvedValue([]);
    vi.spyOn(ingestionService, 'getScanRunResults').mockResolvedValue(null);

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
      expect(screen.getAllByText('FAILED').length).toBeGreaterThan(0);
      expect(screen.queryByText('Open Command Center Results')).toBeNull();
    });
  });
});
