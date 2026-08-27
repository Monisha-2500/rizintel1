import { describe, it, expect, beforeEach, vi } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

import WorkspacePage from '../src/pages/WorkspacePage';
import AssetRegistryPage from '../src/pages/AssetRegistryPage';
import ScanRunsPage from '../src/pages/ScanRunsPage';
import CommandCenter from '../src/pages/CommandCenter';
import * as workspaceService from '../src/services/workspaceService';
import * as findingsService from '../src/services/findingsService';
import * as agentService from '../src/services/agentService';

describe('Phase 1 Frontend Operational Layer', () => {
  const mockOrg = {
    organization_id: 'ORG-DEMO-001',
    display_name: 'RizIntel Demo Organization',
    created_at: '2026-08-24T00:00:00Z',
    is_active: true
  };

  const mockAssets = [
    {
      asset_id: 'ASSET-WEB-001',
      organization_id: 'ORG-DEMO-001',
      display_name: 'Payments API Gateway',
      host: 'payments.demo.corp',
      normalized_host: 'payments.demo.corp',
      port: 443,
      environment: 'production',
      criticality: 'CRITICAL',
      internet_facing: true,
      data_sensitivity: 'RESTRICTED',
      authorization_status: 'AUTHORIZED',
      created_by: 'usr-lead-003',
      created_at: '2026-08-24T00:00:00Z',
      updated_at: '2026-08-24T00:00:00Z'
    },
    {
      asset_id: 'ASSET-WEB-002',
      organization_id: 'ORG-DEMO-001',
      display_name: 'Staging Portal',
      host: 'staging.demo.corp',
      normalized_host: 'staging.demo.corp',
      port: 8080,
      environment: 'staging',
      criticality: 'MEDIUM',
      internet_facing: false,
      data_sensitivity: 'INTERNAL',
      authorization_status: 'PENDING',
      created_by: 'usr-analyst-002',
      created_at: '2026-08-24T00:00:00Z',
      updated_at: '2026-08-24T00:00:00Z'
    }
  ];

  const mockScanRuns = [
    {
      scan_run_id: 'SR-000000000001',
      organization_id: 'ORG-DEMO-001',
      asset_id: 'ASSET-WEB-001',
      created_by_user_id: 'usr-lead-003',
      status: 'WAITING_FOR_INPUT',
      scanner_selections: ['ZAP', 'NUCLEI'],
      data_origin: 'LIVE_SCAN',
      created_at: '2026-08-24T00:00:00Z',
      updated_at: '2026-08-24T00:00:00Z'
    }
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(workspaceService, 'getMyOrganizations').mockResolvedValue([mockOrg]);
    vi.spyOn(workspaceService, 'getRegisteredAssets').mockResolvedValue(mockAssets);
    vi.spyOn(workspaceService, 'getScanRuns').mockResolvedValue(mockScanRuns);
    vi.spyOn(agentService, 'listScannerAgents').mockResolvedValue([
      {
        agent_id: 'AGENT-DEMO-001',
        status: 'ACTIVE',
        capabilities_json: JSON.stringify({
          NUCLEI: { available: true },
          ZAP: { available: true },
          WAPITI: { available: true }
        })
      }
    ]);
  });

  it('renders workspace with authenticated organization', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    render(
      <MemoryRouter initialEntries={['/workspace']}>
        <Routes>
          <Route path="/workspace" element={<WorkspacePage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('RizIntel Demo Organization')).toBeDefined();
    });

    expect(screen.getByText('Registered Assets')).toBeDefined();
    expect(screen.getByText('Active Scan Runs')).toBeDefined();
  });

  it('renders read-only view for Viewer role on Asset Registry', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-viewer-001',
      role: 'VIEWER',
      display_name: 'Auditor View'
    });

    render(
      <MemoryRouter initialEntries={['/asset-registry']}>
        <Routes>
          <Route path="/asset-registry" element={<AssetRegistryPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Asset Registry' })).toBeDefined();
    });

    // Register button should NOT be rendered for Viewer
    expect(screen.queryByText('Register Asset')).toBeNull();
    expect(screen.getByText(/Read-Only Access/i)).toBeDefined();
  });

  it('allows Security Lead/Admin to perform asset authorization actions', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    const patchSpy = vi.spyOn(workspaceService, 'updateAssetStatus').mockResolvedValue({
      ...mockAssets[1],
      authorization_status: 'AUTHORIZED'
    });

    render(
      <MemoryRouter initialEntries={['/asset-registry']}>
        <Routes>
          <Route path="/asset-registry" element={<AssetRegistryPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Register Asset')).toBeDefined();
    });

    const authorizeBtn = screen.getByText('Authorize');
    expect(authorizeBtn).toBeDefined();

    fireEvent.click(authorizeBtn);

    // Confirmation modal should open
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Authorize Asset' })).toBeDefined();
    });

    const modalAuthorizeBtn = screen.getAllByText('Authorize Asset')[1] || screen.getAllByText('Authorize Asset')[0];
    fireEvent.click(modalAuthorizeBtn);

    await waitFor(() => {
      expect(patchSpy).toHaveBeenCalledWith('ORG-DEMO-001', 'ASSET-WEB-002', 'AUTHORIZED');
    });
  });

  it('shows API failure error state and allows retry', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    vi.spyOn(workspaceService, 'getRegisteredAssets').mockRejectedValueOnce(new Error('Network connection failed'));

    render(
      <MemoryRouter initialEntries={['/asset-registry']}>
        <Routes>
          <Route path="/asset-registry" element={<AssetRegistryPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Unable to load assets')).toBeDefined();
    });

    const retryBtn = screen.getByText('Retry');
    expect(retryBtn).toBeDefined();

    vi.spyOn(workspaceService, 'getRegisteredAssets').mockResolvedValueOnce(mockAssets);
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('Payments API Gateway')).toBeDefined();
    });
  });

  it('shows truthful empty state on zero assets', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    vi.spyOn(workspaceService, 'getRegisteredAssets').mockResolvedValue([]);

    render(
      <MemoryRouter initialEntries={['/asset-registry']}>
        <Routes>
          <Route path="/asset-registry" element={<AssetRegistryPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('No assets registered yet')).toBeDefined();
    });

    expect(screen.getAllByText('Register Asset').length).toBeGreaterThan(0);
  });

  it('opens and submits Register Asset modal for Security Lead', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-lead-003',
      role: 'SECURITY_LEAD',
      display_name: 'SOC Lead'
    });

    const registerSpy = vi.spyOn(workspaceService, 'registerAsset').mockResolvedValue({
      asset_id: 'ASSET-NEW-001',
      display_name: 'New Payments Microservice',
      host: 'newpay.corp',
      port: 443,
      authorization_status: 'PENDING'
    });

    render(
      <MemoryRouter initialEntries={['/asset-registry']}>
        <Routes>
          <Route path="/asset-registry" element={<AssetRegistryPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Register Asset')).toBeDefined();
    });

    fireEvent.click(screen.getByText('Register Asset'));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Register Asset' })).toBeDefined();
    });

    const nameInput = screen.getByPlaceholderText('e.g. Payments API');
    const hostInput = screen.getByPlaceholderText('e.g. api.example.com');

    fireEvent.change(nameInput, { target: { value: 'New Payments Microservice' } });
    fireEvent.change(hostInput, { target: { value: 'newpay.corp' } });

    const form = document.getElementById('register-asset-form');
    fireEvent.submit(form);

    await waitFor(() => {
      expect(registerSpy).toHaveBeenCalledWith('ORG-DEMO-001', expect.objectContaining({
        host: 'newpay.corp',
        environment: 'production'
      }));
    });
  });

  it('creates valid scan-run that reaches WAITING_FOR_INPUT', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-analyst-002',
      role: 'ANALYST',
      display_name: 'SA Analyst'
    });

    const createSpy = vi.spyOn(workspaceService, 'createScanRun').mockResolvedValue({
      scan_run_id: 'SR-NEW-999999',
      organization_id: 'ORG-DEMO-001',
      asset_id: 'ASSET-WEB-001',
      created_by_user_id: 'usr-analyst-002',
      status: 'WAITING_FOR_INPUT',
      scanner_selections: ['ZAP', 'NUCLEI'],
      data_origin: 'LIVE_SCAN',
      created_at: '2026-08-24T00:00:00Z',
      updated_at: '2026-08-24T00:00:00Z'
    });

    render(
      <MemoryRouter initialEntries={['/scan-runs']}>
        <Routes>
          <Route path="/scan-runs" element={<ScanRunsPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('SR-000000000001')).toBeDefined();
    });

    const newBtn = screen.getByText('New Scan Run');
    fireEvent.click(newBtn);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Create Scan Run' })).toBeDefined();
    });

    const submitBtn = screen.getByRole('button', { name: 'Create Scan Run' });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledWith('ORG-DEMO-001', {
        asset_id: 'ASSET-WEB-001',
        scanner_selections: expect.arrayContaining(['ZAP', 'NUCLEI']),
        data_origin: 'LIVE_SCAN'
      });
    });
  });

  it('ensures Command Center remains reachable at /command-center', async () => {
    vi.spyOn(findingsService, 'getCurrentUser').mockReturnValue({
      user_id: 'usr-analyst-002',
      role: 'ANALYST',
      display_name: 'SA Analyst'
    });

    render(
      <MemoryRouter initialEntries={['/command-center']}>
        <Routes>
          <Route path="/command-center" element={<CommandCenter />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Command Center/i).length).toBeGreaterThan(0);
    });
  });
});
