import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ScannerAgentsPage from '../src/pages/ScannerAgentsPage';
import * as agentService from '../src/services/agentService';

vi.mock('../src/services/agentService');

describe('Phase 4 — Scanner Agents UI', () => {

  const mockOrg = {
    organization_id: 'ORG-TEST-123',
    name: 'Security Ops Corp',
  };

  const mockUserLead = {
    user_id: 'USR-LEAD',
    role: 'SECURITY_LEAD',
  };

  const mockUserAnalyst = {
    user_id: 'USR-ANALYST',
    role: 'ANALYST',
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders scanner agents page title and list', async () => {
    agentService.listScannerAgents.mockResolvedValue([
      {
        agent_id: 'AGENT-001',
        display_name: 'prod-east-agent',
        status: 'ACTIVE',
        created_at: '2026-08-25T12:00:00Z',
        last_seen_at: '2026-08-25T12:05:00Z',
      },
    ]);

    render(<ScannerAgentsPage currentOrg={mockOrg} currentUser={mockUserLead} />);

    expect(screen.getByRole('heading', { name: /^Scanner Agents$/i })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('prod-east-agent')).toBeInTheDocument();
      expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    });
  });

  it('allows Security Lead to register a new agent and shows single-time secret', async () => {
    agentService.listScannerAgents.mockResolvedValue([]);
    agentService.registerScannerAgent.mockResolvedValue({
      agent: {
        agent_id: 'AGENT-NEW-01',
        display_name: 'new-agent-01',
        status: 'ACTIVE',
      },
      plaintext_secret: 'agt_super_secret_token_123',
    });

    render(<ScannerAgentsPage currentOrg={mockOrg} currentUser={mockUserLead} />);

    const regBtn = screen.getByText(/\+ Register Scanner Agent/i);
    fireEvent.click(regBtn);

    const input = screen.getByPlaceholderText(/prod-us-east-agent-01/i);
    fireEvent.change(input, { target: { value: 'new-agent-01' } });

    const submitBtn = screen.getByRole('button', { name: /Register Agent/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(agentService.registerScannerAgent).toHaveBeenCalledWith('ORG-TEST-123', 'new-agent-01');
      expect(screen.getByText(/agt_super_secret_token_123/i)).toBeInTheDocument();
    });
  });

  it('hides registration button for Analyst role', async () => {
    agentService.listScannerAgents.mockResolvedValue([]);

    render(<ScannerAgentsPage currentOrg={mockOrg} currentUser={mockUserAnalyst} />);

    expect(screen.queryByText(/\+ Register Scanner Agent/i)).not.toBeInTheDocument();
  });

});
