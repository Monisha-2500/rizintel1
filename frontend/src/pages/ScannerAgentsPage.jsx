import React, { useState, useEffect } from 'react';
import { 
  Server, Plus, RefreshCw, CheckCircle2, AlertCircle, ShieldCheck, 
  Lock, Copy, Check, X, Search, Filter, Trash2, Eye, ExternalLink, Activity, Info, BookOpen
} from 'lucide-react';
import { getCurrentUser } from '../services/findingsService';
import { getMyOrganizations } from '../services/workspaceService';
import { listScannerAgents, registerScannerAgent, revokeScannerAgent } from '../services/agentService';

export default function ScannerAgentsPage({ currentOrg: propOrg, currentUser: propUser }) {
  const currentUser = propUser || getCurrentUser();
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState(propOrg || null);
  
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Search & Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [scannerFilter, setScannerFilter] = useState('ALL');

  // Modals state
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [capabilities, setCapabilities] = useState({
    NUCLEI: true,
    ZAP: false,
    WAPITI: false,
  });

  const [newAgentSecret, setNewAgentSecret] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);

  // Revoke modal state
  const [revokeAgentTarget, setRevokeAgentTarget] = useState(null);
  const [revoking, setRevoking] = useState(false);

  // Details drawer state
  const [detailAgent, setDetailAgent] = useState(null);

  // Setup Guide modal state
  const [showSetupGuideModal, setShowSetupGuideModal] = useState(false);
  const [guideTab, setGuideTab] = useState('quickstart'); // 'quickstart' | 'docker' | 'env' | 'security'
  const [copiedSnippet, setCopiedSnippet] = useState(null);

  // Toast state
  const [toast, setToast] = useState(null);

  const isLeadOrAdmin = currentUser?.role === 'SECURITY_LEAD' || currentUser?.role === 'ADMIN';

  useEffect(() => {
    loadData();
  }, [propOrg?.organization_id]);

  // Modal Escape key listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (newAgentSecret) setNewAgentSecret(null);
        else if (revokeAgentTarget) setRevokeAgentTarget(null);
        else if (showRegisterModal) setShowRegisterModal(false);
        else if (detailAgent) setDetailAgent(null);
        else if (showSetupGuideModal) setShowSetupGuideModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [newAgentSecret, revokeAgentTarget, showRegisterModal, detailAgent, showSetupGuideModal]);

  const showToastNotification = (text, type = 'success') => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 4000);
  };

  async function loadData() {
    try {
      setLoading(true);
      setError('');
      
      let orgToUse = selectedOrg || propOrg;
      if (!orgToUse?.organization_id) {
        const orgs = await getMyOrganizations().catch(() => []);
        setOrganizations(orgs);
        if (orgs.length > 0) {
          orgToUse = orgs[0];
          setSelectedOrg(orgToUse);
        }
      }

      if (orgToUse?.organization_id) {
        const data = await listScannerAgents(orgToUse.organization_id);
        setAgents(data || []);
      } else {
        setAgents([]);
      }
    } catch (err) {
      console.error('Failed to load scanner agents:', err);
      setError(err.message || 'Unable to load scanner agents');
    } finally {
      setLoading(false);
    }
  }

  const handleOrgChange = async (orgId) => {
    const org = organizations.find(o => o.organization_id === orgId);
    if (!org) return;
    setSelectedOrg(org);
    try {
      setLoading(true);
      setError('');
      const data = await listScannerAgents(orgId);
      setAgents(data || []);
    } catch (err) {
      setError(err.message || 'Failed to load agents for organization');
    } finally {
      setLoading(false);
    }
  };

  async function handleRegisterSubmit(e) {
    e.preventDefault();
    if (!displayName.trim()) return;
    const activeOrgId = selectedOrg?.organization_id || propOrg?.organization_id;
    if (!activeOrgId) return;

    try {
      setSubmitting(true);
      setError('');
      
      const res = await registerScannerAgent(activeOrgId, displayName.trim());
      
      setNewAgentSecret(res);
      setShowRegisterModal(false);
      setDisplayName('');
      setDescription('');
      showToastNotification('Scanner agent registered successfully.');
      await loadData();
    } catch (err) {
      setError(err.message || 'Failed to register agent.');
    } finally {
      setSubmitting(false);
    }
  }

  async function confirmRevoke() {
    if (!revokeAgentTarget) return;
    const activeOrgId = selectedOrg?.organization_id || propOrg?.organization_id;
    if (!activeOrgId) return;

    try {
      setRevoking(true);
      setError('');
      await revokeScannerAgent(activeOrgId, revokeAgentTarget.agent_id);
      showToastNotification(`Agent ${revokeAgentTarget.display_name} has been revoked.`);
      setRevokeAgentTarget(null);
      await loadData();
    } catch (err) {
      setError(err.message || 'Failed to revoke scanner agent.');
    } finally {
      setRevoking(false);
    }
  }

  function copySecretToClipboard() {
    if (newAgentSecret?.plaintext_secret) {
      navigator.clipboard.writeText(newAgentSecret.plaintext_secret);
      setCopySuccess(true);
      showToastNotification('Agent token copied to clipboard.');
      setTimeout(() => setCopySuccess(false), 3000);
    }
  }

  const formatLastSeen = (lastSeenAt) => {
    if (!lastSeenAt) return 'Never connected';
    const diffMs = Date.now() - new Date(lastSeenAt).getTime();
    if (diffMs < 60000) {
      const secs = Math.max(1, Math.floor(diffMs / 1000));
      return `${secs}s ago`;
    }
    if (diffMs < 3600000) {
      const mins = Math.floor(diffMs / 60000);
      return `${mins}m ago`;
    }
    return new Date(lastSeenAt).toLocaleString();
  };

  // Metrics computation
  const totalAgents = agents.length;
  const onlineAgents = agents.filter(a => a.status === 'ACTIVE' || a.status === 'ONLINE').length;
  const offlineAgents = agents.filter(a => a.status === 'OFFLINE' || a.status === 'INACTIVE').length;
  const revokedAgents = agents.filter(a => a.status === 'REVOKED').length;

  // Filter logic
  const filteredAgents = agents.filter(agent => {
    const matchQuery = !searchQuery.trim() || 
      agent.display_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.agent_id.toLowerCase().includes(searchQuery.toLowerCase());
    
    let matchStatus = true;
    if (statusFilter === 'ONLINE') matchStatus = agent.status === 'ACTIVE' || agent.status === 'ONLINE';
    if (statusFilter === 'OFFLINE') matchStatus = agent.status === 'OFFLINE' || agent.status === 'INACTIVE';
    if (statusFilter === 'REVOKED') matchStatus = agent.status === 'REVOKED';

    let matchScanner = true;
    if (scannerFilter !== 'ALL') {
      try {
        const caps = typeof agent.capabilities_json === 'string' ? JSON.parse(agent.capabilities_json || '{}') : (agent.capabilities || {});
        matchScanner = Boolean(caps[scannerFilter]?.available || caps[scannerFilter]);
      } catch {
        matchScanner = true;
      }
    }

    return matchQuery && matchStatus && matchScanner;
  });

  return (
    <div style={{ padding: '8px 0 24px', width: '100%', maxWidth: '100%', boxSizing: 'border-box', fontFamily: 'var(--font-sans, system-ui, sans-serif)' }}>
      
      {/* Toast Notification Container */}
      {toast && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 3000,
          background: toast.type === 'error' ? '#EF4444' : '#10B981',
          color: '#FFFFFF',
          padding: '12px 20px',
          borderRadius: '10px',
          boxShadow: '0 10px 25px rgba(0,0,0,0.2)',
          fontSize: '13.5px',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          animation: 'fade-in 0.2s ease-out'
        }}>
          {toast.type === 'error' ? <AlertCircle size={18} /> : <CheckCircle2 size={18} />}
          <span>{toast.text}</span>
          <button 
            onClick={() => setToast(null)}
            style={{ background: 'none', border: 'none', color: '#FFF', cursor: 'pointer', marginLeft: '8px', padding: 0 }}
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Page Header */}
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        marginBottom: '24px',
        paddingBottom: '16px',
        borderBottom: '1px solid var(--border-color, #E2E8F0)',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: '700', margin: '0 0 4px 0', color: 'var(--text-primary, #0F172A)', letterSpacing: '-0.3px' }}>
              Scanner Agents
            </h1>
            {!isLeadOrAdmin && (
              <span style={{ 
                display: 'inline-flex', 
                alignItems: 'center', 
                gap: '4px', 
                fontSize: '12px', 
                fontWeight: '600', 
                color: '#64748B', 
                background: '#F1F5F9', 
                padding: '3px 10px', 
                borderRadius: '12px',
                border: '1px solid #E2E8F0'
              }}>
                <Lock size={12} /> Read-Only Access
              </span>
            )}
          </div>
          <p style={{ fontSize: '13.5px', color: 'var(--text-secondary, #64748B)', margin: '0 0 4px 0' }}>
            Manage secure scanner connections and monitor available scanning capabilities.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {organizations.length > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-card, #FFFFFF)', border: '1px solid var(--border-color, #CBD5E1)', padding: '6px 12px', borderRadius: '10px' }}>
              <Server size={16} color="#6366F1" />
              <select 
                value={selectedOrg?.organization_id || ''} 
                onChange={(e) => handleOrgChange(e.target.value)}
                style={{ background: 'transparent', fontSize: '13.5px', fontWeight: '600', color: '#1E293B', border: 'none', outline: 'none', cursor: 'pointer' }}
              >
                {organizations.map(o => (
                  <option key={o.organization_id} value={o.organization_id}>{o.display_name}</option>
                ))}
              </select>
            </div>
          )}

          {isLeadOrAdmin && (
            <button
              id="register-agent-btn"
              onClick={() => { setShowRegisterModal(true); setNewAgentSecret(null); }}
              style={{
                background: '#4F46E5',
                color: '#FFF',
                padding: '9px 18px',
                borderRadius: '10px',
                border: 'none',
                fontWeight: '600',
                fontSize: '13.5px',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                boxShadow: '0 2px 4px rgba(79, 70, 229, 0.25)',
                transition: 'background 0.15s ease'
              }}
            >
              <Plus size={16} />
              <span>+ Register Scanner Agent</span>
            </button>
          )}
        </div>
      </div>

      {/* Dynamic Real Summary Cards */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
        gap: '16px', 
        marginBottom: '24px' 
      }}>
        <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '12px', border: '1px solid var(--border-color, #E2E8F0)', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
          <div style={{ background: 'var(--bg-lavender, #EEF2FF)', color: '#6366F1', padding: '12px', borderRadius: '12px' }}>
            <Server size={22} />
          </div>
          <div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: 'var(--text-primary, #0F172A)', lineHeight: '1.1' }}>{totalAgents}</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #0F172A)', marginTop: '2px' }}>Total Agents</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary, #64748B)' }}>All registered agents</div>
          </div>
        </div>

        <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '12px', border: '1px solid var(--border-color, #E2E8F0)', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
          <div style={{ background: 'rgba(16, 185, 129, 0.12)', color: '#10B981', padding: '12px', borderRadius: '12px' }}>
            <CheckCircle2 size={22} />
          </div>
          <div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#10B981', lineHeight: '1.1' }}>{onlineAgents}</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #0F172A)', marginTop: '2px' }}>Online</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary, #64748B)' }}>Actively connected</div>
          </div>
        </div>

        <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '12px', border: '1px solid var(--border-color, #E2E8F0)', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
          <div style={{ background: 'rgba(245, 158, 11, 0.12)', color: '#F59E0B', padding: '12px', borderRadius: '12px' }}>
            <Activity size={22} />
          </div>
          <div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#F59E0B', lineHeight: '1.1' }}>{offlineAgents}</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #0F172A)', marginTop: '2px' }}>Offline</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary, #64748B)' }}>Not connected</div>
          </div>
        </div>

        <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '12px', border: '1px solid var(--border-color, #E2E8F0)', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
          <div style={{ background: 'rgba(239, 68, 68, 0.12)', color: '#EF4444', padding: '12px', borderRadius: '12px' }}>
            <AlertCircle size={22} />
          </div>
          <div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#EF4444', lineHeight: '1.1' }}>{revokedAgents}</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #0F172A)', marginTop: '2px' }}>Revoked</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary, #64748B)' }}>Access revoked</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Controls + Agent List (Left) & Info Cards (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '24px', alignItems: 'start' }}>
        
        {/* Left Column: Agent Table & Controls */}
        <div>
          {/* Controls Bar: Search & Filter */}
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between', 
            gap: '14px', 
            marginBottom: '20px', 
            flexWrap: 'wrap' 
          }}>
            <div style={{ flex: '1', minWidth: '220px', position: 'relative' }}>
              <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#94A3B8' }} />
              <input
                type="text"
                placeholder="Search by agent name or ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 14px 9px 40px',
                  borderRadius: '10px',
                  border: '1px solid var(--border-color, #E2E8F0)',
                  background: 'var(--bg-input, #FFFFFF)',
                  fontSize: '13.5px',
                  color: 'var(--text-primary, #0F172A)',
                  boxSizing: 'border-box',
                  outline: 'none'
                }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12.5px', color: 'var(--text-secondary, #64748B)', fontWeight: '500' }}>Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-color, #CBD5E1)',
                    background: 'var(--bg-input, #FFFFFF)',
                    fontSize: '13px',
                    fontWeight: '600',
                    color: 'var(--text-primary, #1E293B)',
                    cursor: 'pointer'
                  }}
                >
                  <option value="ALL">All Statuses</option>
                  <option value="ONLINE">Online</option>
                  <option value="OFFLINE">Offline</option>
                  <option value="REVOKED">Revoked</option>
                </select>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12.5px', color: 'var(--text-secondary, #64748B)', fontWeight: '500' }}>Scanner:</span>
                <select
                  value={scannerFilter}
                  onChange={(e) => setScannerFilter(e.target.value)}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-color, #CBD5E1)',
                    background: 'var(--bg-input, #FFFFFF)',
                    fontSize: '13px',
                    fontWeight: '600',
                    color: 'var(--text-primary, #1E293B)',
                    cursor: 'pointer'
                  }}
                >
                  <option value="ALL">All Scanners</option>
                  <option value="NUCLEI">Nuclei</option>
                  <option value="ZAP">OWASP ZAP</option>
                  <option value="WAPITI">Wapiti</option>
                </select>
              </div>

              <button
                onClick={loadData}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 14px',
                  borderRadius: '8px',
                  border: '1px solid var(--border-color, #CBD5E1)',
                  background: 'var(--bg-card, #FFFFFF)',
                  fontSize: '13px',
                  fontWeight: '600',
                  color: 'var(--text-primary, #475569)',
                  cursor: 'pointer'
                }}
              >
                <RefreshCw size={14} /> Refresh
              </button>
            </div>
          </div>

          {/* Inline Error Banner */}
          {error && (
            <div style={{ background: '#FEF2F2', border: '1px solid #FCA5A5', color: '#991B1B', padding: '16px 20px', borderRadius: '12px', marginBottom: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <AlertCircle size={20} color="#DC2626" />
                <div>
                  <div style={{ fontWeight: '700', fontSize: '14px' }}>Unable to load scanner agents</div>
                  <div style={{ fontSize: '13px', color: '#7F1D1D' }}>{error}</div>
                </div>
              </div>
              <button
                onClick={loadData}
                style={{ padding: '6px 14px', borderRadius: '6px', border: 'none', background: '#DC2626', color: '#FFF', fontWeight: '600', fontSize: '12.5px', cursor: 'pointer' }}
              >
                Retry
              </button>
            </div>
          )}

          {/* Table Container */}
          {loading ? (
            <div style={{ textAlign: 'center', padding: '60px', color: '#64748B', background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)' }}>
              <RefreshCw size={24} className="spin" style={{ marginBottom: '10px', color: '#6366F1' }} />
              <div style={{ fontSize: '14px', fontWeight: '600' }}>Loading scanner agents...</div>
            </div>
          ) : agents.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 20px', background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
              <div style={{ background: 'var(--bg-lavender, #EEF2FF)', width: '52px', height: '52px', borderRadius: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px auto' }}>
                <Server size={26} color="#6366F1" />
              </div>
              <h3 style={{ margin: '0 0 6px 0', color: 'var(--text-primary, #0F172A)', fontSize: '18px', fontWeight: '700' }}>
                No scanner agents connected yet
              </h3>
              <p style={{ color: 'var(--text-secondary, #64748B)', fontSize: '14px', margin: '0 auto 20px auto', maxWidth: '440px', lineHeight: '1.5' }}>
                {isLeadOrAdmin 
                  ? 'Connect a trusted scanner agent before launching automated security scans.' 
                  : 'Scanner agent registration requires Security Lead or Administrator access.'}
              </p>
              {isLeadOrAdmin ? (
                <button
                  onClick={() => { setShowRegisterModal(true); setNewAgentSecret(null); }}
                  style={{
                    background: '#4F46E5',
                    color: '#FFF',
                    padding: '10px 20px',
                    borderRadius: '10px',
                    border: 'none',
                    fontWeight: '600',
                    fontSize: '14px',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px',
                    boxShadow: '0 2px 6px rgba(79, 70, 229, 0.3)'
                  }}
                >
                  <Plus size={16} /> Register First Scanner Agent
                </button>
              ) : (
                <button
                  onClick={loadData}
                  style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-surface-elevated, #FFF)', fontWeight: '600', fontSize: '13px', cursor: 'pointer', color: 'var(--text-primary, #475569)' }}
                >
                  Refresh Agents
                </button>
              )}
            </div>
          ) : filteredAgents.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '50px 20px', background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)' }}>
              <Filter size={32} style={{ color: '#94A3B8', marginBottom: '12px' }} />
              <h3 style={{ margin: '0 0 6px 0', color: 'var(--text-primary, #0F172A)', fontSize: '16px', fontWeight: '700' }}>No scanner agents match your filters</h3>
              <p style={{ color: 'var(--text-secondary, #64748B)', fontSize: '13.5px', margin: '0 0 16px 0' }}>Try adjusting search query or status/scanner filter controls.</p>
              <button
                onClick={() => { setSearchQuery(''); setStatusFilter('ALL'); setScannerFilter('ALL'); }}
                style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-surface-elevated, #FFF)', fontWeight: '600', fontSize: '13px', cursor: 'pointer', color: 'var(--text-primary, #334155)' }}
              >
                Reset Filters
              </button>
            </div>
          ) : (
            <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13.5px' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-surface-elevated, #F8FAFC)', borderBottom: '1px solid var(--border-color, #E2E8F0)', textAlign: 'left', color: 'var(--text-secondary, #64748B)', fontSize: '12px', fontWeight: '700', letterSpacing: '0.3px' }}>
                    <th style={{ padding: '12px 16px' }}>Agent</th>
                    <th style={{ padding: '12px 16px' }}>Capabilities</th>
                    <th style={{ padding: '12px 16px' }}>Status</th>
                    <th style={{ padding: '12px 16px' }}>Last Seen</th>
                    <th style={{ padding: '12px 16px' }}>Registered At</th>
                    <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAgents.map(agent => {
                    const isOnline = agent.status === 'ACTIVE' || agent.status === 'ONLINE';
                    const isRevoked = agent.status === 'REVOKED';

                    return (
                      <tr key={agent.agent_id} style={{ borderBottom: '1px solid var(--border-color, #F1F5F9)' }}>
                        <td style={{ padding: '14px 16px' }}>
                          <div style={{ fontWeight: '700', color: 'var(--text-primary, #0F172A)', fontSize: '14px' }}>{agent.display_name}</div>
                          <div style={{ fontSize: '11.5px', color: 'var(--text-secondary, #64748B)', fontFamily: 'monospace', marginTop: '2px' }}>{agent.agent_id}</div>
                        </td>
                        <td style={{ padding: '14px 16px' }}>
                          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                            {['NUCLEI', 'ZAP', 'WAPITI'].map(scannerKey => {
                              const isAvailable = scannerKey === 'NUCLEI' && isOnline;
                              return (
                                <span 
                                  key={scannerKey}
                                  style={{
                                    fontSize: '11px',
                                    fontWeight: '700',
                                    padding: '2px 8px',
                                    borderRadius: '6px',
                                    background: isAvailable ? 'var(--bg-lavender, #EEF2FF)' : 'var(--bg-surface-elevated, #F1F5F9)',
                                    color: isAvailable ? '#818CF8' : 'var(--text-secondary, #64748B)',
                                    border: `1px solid ${isAvailable ? 'rgba(99, 102, 241, 0.3)' : 'var(--border-color, #E2E8F0)'}`
                                  }}
                                >
                                  {scannerKey === 'NUCLEI' ? 'Nuclei' : scannerKey === 'ZAP' ? 'OWASP ZAP' : 'Wapiti'}
                                </span>
                              );
                            })}
                          </div>
                        </td>
                        <td style={{ padding: '14px 16px' }}>
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            padding: '4px 10px',
                            borderRadius: '12px',
                            fontSize: '12px',
                            fontWeight: '700',
                            background: isOnline ? '#DCFCE7' : isRevoked ? '#FEE2E2' : '#FEF3C7',
                            color: isOnline ? '#15803D' : isRevoked ? '#991B1B' : '#D97706'
                          }}>
                            <span style={{
                              width: '6px', height: '6px', borderRadius: '50%',
                              background: isOnline ? '#16A34A' : isRevoked ? '#DC2626' : '#D97706'
                            }} />
                            {isOnline ? 'ACTIVE' : isRevoked ? 'REVOKED' : 'OFFLINE'}
                          </span>
                        </td>
                        <td style={{ padding: '14px 16px', color: 'var(--text-secondary, #475569)', fontSize: '12.5px' }}>
                          {formatLastSeen(agent.last_seen_at)}
                        </td>
                        <td style={{ padding: '14px 16px', color: 'var(--text-secondary, #64748B)', fontSize: '12.5px' }}>
                          {agent.created_at ? new Date(agent.created_at).toLocaleDateString() : '—'}
                        </td>
                        <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                            <button
                              onClick={() => setDetailAgent(agent)}
                              style={{
                                padding: '5px 10px',
                                borderRadius: '6px',
                                border: '1px solid var(--border-color, #CBD5E1)',
                                background: 'var(--bg-surface-elevated, #FFF)',
                                fontSize: '12px',
                                fontWeight: '600',
                                color: 'var(--text-primary, #475569)',
                                cursor: 'pointer'
                              }}
                            >
                              Details
                            </button>
                            {isLeadOrAdmin && !isRevoked && (
                              <button
                                onClick={() => setRevokeAgentTarget(agent)}
                                style={{
                                  padding: '5px 10px',
                                  borderRadius: '6px',
                                  border: 'none',
                                  background: '#FEF2F2',
                                  color: '#DC2626',
                                  fontSize: '12px',
                                  fontWeight: '600',
                                  cursor: 'pointer'
                                }}
                              >
                                Revoke
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: Guidance & Info Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* About Scanner Agents Card */}
          <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <Info size={18} color="#6366F1" />
              <h3 style={{ fontSize: '14px', fontWeight: '700', margin: 0, color: 'var(--text-primary, #0F172A)' }}>About Scanner Agents</h3>
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary, #64748B)', margin: '0 0 12px 0', lineHeight: '1.45' }}>
              Scanner agents are trusted machines that run approved scanner engines and communicate securely with RizIntel.
            </p>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary, #475569)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li>Agents authenticate using a one-time token.</li>
              <li>Tokens are securely stored server-side as a hash.</li>
              <li>Only online active agents can execute scan runs.</li>
              <li>Revoked agents immediately lose system access.</li>
            </ul>
          </div>

          {/* Need Help Setting Up Card */}
          <div style={{ background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <BookOpen size={18} color="#10B981" />
              <h3 style={{ fontSize: '14px', fontWeight: '700', margin: 0, color: 'var(--text-primary, #0F172A)' }}>Need Help Setting Up?</h3>
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary, #64748B)', margin: '0 0 14px 0', lineHeight: '1.45' }}>
              Follow our step-by-step guide to install and configure a scanner agent host.
            </p>
            <button
              id="open-setup-guide-btn"
              onClick={() => setShowSetupGuideModal(true)}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '8px',
                border: '1px solid var(--border-color, #CBD5E1)',
                background: 'var(--bg-surface-elevated, #FFF)',
                fontSize: '12.5px',
                fontWeight: '600',
                color: 'var(--text-primary, #334155)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                transition: 'all 0.15s ease'
              }}
            >
              <span>View Setup Guide</span>
              <BookOpen size={14} />
            </button>
          </div>

          {/* Security Notice Card */}
          <div style={{ background: 'var(--bg-card, #F8FAFC)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)', padding: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <ShieldCheck size={18} color="#F59E0B" />
              <h3 style={{ fontSize: '13.5px', fontWeight: '700', margin: 0, color: 'var(--text-primary, #0F172A)' }}>Security Notice</h3>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary, #64748B)', margin: 0, lineHeight: '1.45' }}>
              Keep agent tokens secure. They grant authorization to execute scans. You will only see the token once during registration.
            </p>
          </div>
        </div>

      </div>

      {/* One-Time Token Modal (Shown ONCE after successful registration) */}
      {newAgentSecret && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setNewAgentSecret(null); }}
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 3000, padding: '16px'
          }}
        >
          <div style={{
            background: '#FFFFFF',
            borderRadius: '16px',
            padding: '28px',
            width: '100%',
            maxWidth: '540px',
            boxShadow: '0 25px 50px -12px rgba(0,0,0,0.25)',
            position: 'relative'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ background: '#DCFCE7', color: '#16A34A', padding: '8px', borderRadius: '10px' }}>
                  <CheckCircle2 size={20} />
                </div>
                <h2 style={{ fontSize: '18px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                  Agent Registered Successfully
                </h2>
              </div>
              <button
                onClick={() => setNewAgentSecret(null)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748B', padding: 0 }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ background: '#FEF3C7', border: '1px solid #FDE68A', padding: '12px 14px', borderRadius: '10px', fontSize: '13px', color: '#92400E', marginBottom: '16px', lineHeight: '1.45' }}>
              <strong>Save this token now. It will not be shown again.</strong> Copy and store this secret in your scanner agent environment variable (<code>RIZINTEL_AGENT_TOKEN</code>).
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '20px' }}>
              <code style={{
                flex: 1,
                background: '#0F172A',
                color: '#38BDF8',
                padding: '12px 14px',
                borderRadius: '8px',
                fontSize: '13.5px',
                fontFamily: 'monospace',
                wordBreak: 'break-all'
              }}>
                {newAgentSecret.plaintext_secret}
              </code>
              <button
                onClick={copySecretToClipboard}
                style={{
                  padding: '12px 16px',
                  background: copySuccess ? '#059669' : '#4F46E5',
                  color: '#FFFFFF',
                  border: 'none',
                  borderRadius: '8px',
                  fontWeight: '600',
                  fontSize: '13px',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
              >
                {copySuccess ? 'Copied!' : 'Copy Token'}
              </button>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setNewAgentSecret(null)}
                style={{
                  padding: '9px 18px',
                  background: '#10B981',
                  color: '#FFF',
                  border: 'none',
                  borderRadius: '8px',
                  fontWeight: '600',
                  fontSize: '13.5px',
                  cursor: 'pointer'
                }}
              >
                I Have Saved This Token
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Register Agent Modal */}
      {showRegisterModal && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setShowRegisterModal(false); }}
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2000, padding: '16px'
          }}
        >
          <div style={{
            background: '#FFFFFF',
            borderRadius: '14px',
            padding: '24px 28px',
            width: '100%',
            maxWidth: '480px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            position: 'relative'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
              <h2 style={{ fontSize: '18px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                Register Scanner Agent
              </h2>
              <button
                onClick={() => setShowRegisterModal(false)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748B', padding: 0 }}
              >
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleRegisterSubmit}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                  Display Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. prod-us-east-agent-01"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '13.5px', boxSizing: 'border-box', outline: 'none' }}
                />
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '8px', color: '#334155' }}>
                  Supported Scanner Capabilities
                </label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {[
                    { key: 'NUCLEI', label: 'Nuclei', desc: 'Vulnerability & misconfiguration scanner' },
                    { key: 'ZAP', label: 'OWASP ZAP', desc: 'Web application security scanner' },
                    { key: 'WAPITI', label: 'Wapiti', desc: 'Web application vulnerability scanner' }
                  ].map(sc => (
                    <label key={sc.key} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 12px', borderRadius: '8px', border: '1px solid #E2E8F0', background: '#F8FAFC', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={capabilities[sc.key]}
                        onChange={() => setCapabilities(prev => ({ ...prev, [sc.key]: !prev[sc.key] }))}
                      />
                      <div>
                        <span style={{ fontSize: '13px', fontWeight: '700', color: '#0F172A' }}>{sc.label}</span>
                        <span style={{ fontSize: '11.5px', color: '#64748B', marginLeft: '8px' }}>{sc.desc}</span>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px', color: '#334155' }}>
                  Description (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="e.g. Primary production scanner node in US-East"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '13.5px', boxSizing: 'border-box', fontFamily: 'inherit' }}
                />
              </div>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  style={{ padding: '9px 18px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', cursor: 'pointer', fontSize: '13.5px', fontWeight: '600', color: '#475569' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !displayName.trim()}
                  style={{
                    padding: '9px 18px',
                    borderRadius: '8px',
                    border: 'none',
                    background: submitting || !displayName.trim() ? '#94A3B8' : '#4F46E5',
                    color: '#FFF',
                    fontWeight: '600',
                    fontSize: '13.5px',
                    cursor: submitting || !displayName.trim() ? 'not-allowed' : 'pointer'
                  }}
                >
                  {submitting ? 'Registering...' : 'Register Agent'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revocation Confirmation Modal */}
      {revokeAgentTarget && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setRevokeAgentTarget(null); }}
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2500, padding: '16px'
          }}
        >
          <div style={{
            background: '#FFFFFF',
            borderRadius: '14px',
            padding: '24px 28px',
            width: '100%',
            maxWidth: '460px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            position: 'relative'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <AlertCircle size={22} color="#DC2626" />
                <h3 style={{ fontSize: '17px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                  Revoke Scanner Agent?
                </h3>
              </div>
              <button
                onClick={() => setRevokeAgentTarget(null)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748B', padding: 0 }}
              >
                <X size={18} />
              </button>
            </div>

            <p style={{ fontSize: '13.5px', color: '#475569', margin: '0 0 16px 0', lineHeight: '1.5' }}>
              Revoking <strong>{revokeAgentTarget.display_name}</strong> immediately prevents it from authenticating or claiming new scanner jobs. Machine identity authentication will be permanently disabled.
            </p>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setRevokeAgentTarget(null)}
                style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', fontWeight: '600', fontSize: '13px', cursor: 'pointer', color: '#475569' }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmRevoke}
                disabled={revoking}
                style={{ padding: '8px 16px', borderRadius: '8px', border: 'none', background: '#DC2626', color: '#FFF', fontWeight: '600', fontSize: '13px', cursor: 'pointer' }}
              >
                {revoking ? 'Revoking...' : 'Revoke Agent'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Agent Details Drawer / Modal */}
      {detailAgent && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setDetailAgent(null); }}
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2000, padding: '16px'
          }}
        >
          <div style={{
            background: '#FFFFFF',
            borderRadius: '14px',
            padding: '24px 28px',
            width: '100%',
            maxWidth: '500px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            position: 'relative'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '17px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                Agent Details
              </h3>
              <button
                onClick={() => setDetailAgent(null)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748B', padding: 0 }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
              <div>
                <span style={{ color: '#64748B', fontWeight: '600' }}>Display Name:</span>
                <div style={{ fontWeight: '700', color: '#0F172A', fontSize: '14px' }}>{detailAgent.display_name}</div>
              </div>
              <div>
                <span style={{ color: '#64748B', fontWeight: '600' }}>Agent ID:</span>
                <div style={{ fontFamily: 'monospace', color: '#334155' }}>{detailAgent.agent_id}</div>
              </div>
              <div>
                <span style={{ color: '#64748B', fontWeight: '600' }}>Organization:</span>
                <div style={{ color: '#334155' }}>{detailAgent.organization_id}</div>
              </div>
              <div>
                <span style={{ color: '#64748B', fontWeight: '600' }}>Status:</span>
                <div style={{ fontWeight: '700', color: detailAgent.status === 'ACTIVE' || detailAgent.status === 'ONLINE' ? '#15803D' : detailAgent.status === 'REVOKED' ? '#991B1B' : '#D97706' }}>
                  {detailAgent.status}
                </div>
              </div>
              <div>
                <span style={{ color: '#64748B', fontWeight: '600' }}>Last Seen:</span>
                <div style={{ color: '#334155' }}>{formatLastSeen(detailAgent.last_seen_at)}</div>
              </div>
              <div>
                <span style={{ color: '#64748B', fontWeight: '600' }}>Registered At:</span>
                <div style={{ color: '#334155' }}>{detailAgent.created_at ? new Date(detailAgent.created_at).toLocaleString() : '—'}</div>
              </div>
              {detailAgent.revoked_at && (
                <div>
                  <span style={{ color: '#64748B', fontWeight: '600' }}>Revoked At:</span>
                  <div style={{ color: '#991B1B' }}>{new Date(detailAgent.revoked_at).toLocaleString()}</div>
                </div>
              )}
            </div>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setDetailAgent(null)}
                style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', fontWeight: '600', fontSize: '13px', cursor: 'pointer', color: '#475569' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Setup Guide Modal */}
      {showSetupGuideModal && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setShowSetupGuideModal(false); }}
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2100, padding: '16px'
          }}
        >
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            borderRadius: '18px',
            padding: '32px 38px',
            width: '94%',
            maxWidth: '1100px',
            maxHeight: '92vh',
            overflowY: 'auto',
            boxShadow: '0 25px 50px -12px rgba(0,0,0,0.25)',
            position: 'relative'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid var(--border-color, #E2E8F0)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '42px', height: '42px', borderRadius: '12px',
                  background: 'linear-gradient(135deg, #10B981 0%, #059669 100%)',
                  color: '#FFF', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  boxShadow: '0 4px 12px rgba(16, 185, 129, 0.25)', flexShrink: 0
                }}>
                  <BookOpen size={22} />
                </div>
                <div>
                  <h2 style={{ fontSize: '19px', fontWeight: '700', margin: '0 0 2px 0', color: 'var(--text-primary, #0F172A)' }}>
                    Scanner Agent Host Setup Guide
                  </h2>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary, #64748B)', margin: 0 }}>
                    Step-by-step instructions to configure, authenticate, and run a trusted scanner agent host.
                  </p>
                </div>
              </div>

              <button
                id="close-setup-guide-btn"
                onClick={() => setShowSetupGuideModal(false)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px', color: '#64748B', borderRadius: '6px' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Navigation Tabs */}
            <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color, #E2E8F0)', paddingBottom: '12px', marginBottom: '20px' }}>
              {[
                { id: 'quickstart', label: '1. Quickstart (CLI)' },
                { id: 'docker', label: '2. Docker Container' },
                { id: 'env', label: '3. Environment Variables' },
                { id: 'security', label: '4. Security & Architecture' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setGuideTab(tab.id)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: '8px',
                    border: 'none',
                    background: guideTab === tab.id ? '#EEF2FF' : 'transparent',
                    color: guideTab === tab.id ? '#4F46E5' : 'var(--text-secondary, #64748B)',
                    fontWeight: '700',
                    fontSize: '13px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab 1: Quickstart (CLI) */}
            {guideTab === 'quickstart' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', fontSize: '13.5px', color: 'var(--text-primary, #1E293B)' }}>
                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
                    Step 1: Register an Agent in RizIntel UI
                  </h4>
                  <p style={{ margin: '0 0 10px 0', color: '#64748B', lineHeight: '1.5' }}>
                    Click <strong>Register Scanner Agent</strong> on this page. Choose a descriptive host name (e.g. <code>prod-scan-worker-01</code>), select supported engines (Nuclei, ZAP, Wapiti), and copy the generated one-time token.
                  </p>
                </div>

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <h4 style={{ margin: 0, fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
                      Step 2: Clone and Install Agent Daemon
                    </h4>
                    <button
                      onClick={() => {
                        const code = 'git clone https://github.com/rizzolve/rizintel-agent.git\ncd rizintel-agent\npip install -r requirements.txt';
                        navigator.clipboard?.writeText(code);
                        setCopiedSnippet('git');
                        setTimeout(() => setCopiedSnippet(null), 2000);
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', border: '1px solid #CBD5E1', background: '#FFF', fontSize: '11.5px', fontWeight: '600', cursor: 'pointer', color: '#475569' }}
                    >
                      {copiedSnippet === 'git' ? <><Check size={12} color="#10B981" /> Copied!</> : <><Copy size={12} /> Copy</>}
                    </button>
                  </div>
                  <pre style={{ margin: 0, padding: '14px', borderRadius: '10px', background: '#0F172A', color: '#E2E8F0', fontFamily: 'monospace', fontSize: '12.5px', overflowX: 'auto', lineHeight: '1.6' }}>
{`git clone https://github.com/rizzolve/rizintel-agent.git
cd rizintel-agent
pip install -r requirements.txt`}
                  </pre>
                </div>

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <h4 style={{ margin: 0, fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
                      Step 3: Configure Environment Variables
                    </h4>
                    <button
                      onClick={() => {
                        const code = `export RIZINTEL_API_URL="http://127.0.0.1:8000"\nexport RIZINTEL_ORGANIZATION_ID="${selectedOrg?.organization_id || 'ORG-RIZZOLVE-DEMO'}"\nexport RIZINTEL_AGENT_ID="AGENT-YOUR-ID"\nexport RIZINTEL_AGENT_TOKEN="agt_your_secret_token"`;
                        navigator.clipboard?.writeText(code);
                        setCopiedSnippet('env');
                        setTimeout(() => setCopiedSnippet(null), 2000);
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', border: '1px solid #CBD5E1', background: '#FFF', fontSize: '11.5px', fontWeight: '600', cursor: 'pointer', color: '#475569' }}
                    >
                      {copiedSnippet === 'env' ? <><Check size={12} color="#10B981" /> Copied!</> : <><Copy size={12} /> Copy</>}
                    </button>
                  </div>
                  <pre style={{ margin: 0, padding: '14px', borderRadius: '10px', background: '#0F172A', color: '#A5B4FC', fontFamily: 'monospace', fontSize: '12.5px', overflowX: 'auto', lineHeight: '1.6' }}>
{`export RIZINTEL_API_URL="http://127.0.0.1:8000"
export RIZINTEL_ORGANIZATION_ID="${selectedOrg?.organization_id || 'ORG-RIZZOLVE-DEMO'}"
export RIZINTEL_AGENT_ID="AGENT-YOUR-ID"
export RIZINTEL_AGENT_TOKEN="agt_your_secret_token"`}
                  </pre>
                </div>

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <h4 style={{ margin: 0, fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
                      Step 4: Launch Agent Daemon & Heartbeat
                    </h4>
                    <button
                      onClick={() => {
                        const code = 'python -m agent.runner --daemon';
                        navigator.clipboard?.writeText(code);
                        setCopiedSnippet('run');
                        setTimeout(() => setCopiedSnippet(null), 2000);
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', border: '1px solid #CBD5E1', background: '#FFF', fontSize: '11.5px', fontWeight: '600', cursor: 'pointer', color: '#475569' }}
                    >
                      {copiedSnippet === 'run' ? <><Check size={12} color="#10B981" /> Copied!</> : <><Copy size={12} /> Copy</>}
                    </button>
                  </div>
                  <pre style={{ margin: 0, padding: '14px', borderRadius: '10px', background: '#0F172A', color: '#86EFAC', fontFamily: 'monospace', fontSize: '12.5px', overflowX: 'auto', lineHeight: '1.6' }}>
{`python -m agent.runner --daemon`}
                  </pre>
                  <p style={{ margin: '8px 0 0 0', color: '#64748B', fontSize: '12.5px' }}>
                    Once launched, the agent emits regular 30-second heartbeats to RizIntel API. Status will switch to <strong style={{ color: '#15803D' }}>ACTIVE</strong> automatically.
                  </p>
                </div>
              </div>
            )}

            {/* Tab 2: Docker Container */}
            {guideTab === 'docker' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', fontSize: '13.5px' }}>
                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
                    Option A: Docker CLI One-Liner
                  </h4>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontSize: '12px', color: '#64748B' }}>Run standalone containerized agent with pre-bundled Nuclei & ZAP:</span>
                    <button
                      onClick={() => {
                        const code = `docker run -d \\\n  --name rizintel-scanner-agent \\\n  --restart unless-stopped \\\n  -e RIZINTEL_API_URL="http://host.docker.internal:8000" \\\n  -e RIZINTEL_ORGANIZATION_ID="${selectedOrg?.organization_id || 'ORG-RIZZOLVE-DEMO'}" \\\n  -e RIZINTEL_AGENT_ID="AGENT-YOUR-ID" \\\n  -e RIZINTEL_AGENT_TOKEN="agt_your_secret_token" \\\n  rizzolve/scanner-agent:latest`;
                        navigator.clipboard?.writeText(code);
                        setCopiedSnippet('docker-run');
                        setTimeout(() => setCopiedSnippet(null), 2000);
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', border: '1px solid #CBD5E1', background: '#FFF', fontSize: '11.5px', fontWeight: '600', cursor: 'pointer', color: '#475569' }}
                    >
                      {copiedSnippet === 'docker-run' ? <><Check size={12} color="#10B981" /> Copied!</> : <><Copy size={12} /> Copy</>}
                    </button>
                  </div>
                  <pre style={{ margin: 0, padding: '14px', borderRadius: '10px', background: '#0F172A', color: '#A5B4FC', fontFamily: 'monospace', fontSize: '12.5px', overflowX: 'auto', lineHeight: '1.6' }}>
{`docker run -d \\
  --name rizintel-scanner-agent \\
  --restart unless-stopped \\
  -e RIZINTEL_API_URL="http://host.docker.internal:8000" \\
  -e RIZINTEL_ORGANIZATION_ID="${selectedOrg?.organization_id || 'ORG-RIZZOLVE-DEMO'}" \\
  -e RIZINTEL_AGENT_ID="AGENT-YOUR-ID" \\
  -e RIZINTEL_AGENT_TOKEN="agt_your_secret_token" \\
  rizzolve/scanner-agent:latest`}
                  </pre>
                </div>

                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
                    Option B: Docker Compose (`docker-compose.yml`)
                  </h4>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontSize: '12px', color: '#64748B' }}>Production multi-container orchestration:</span>
                    <button
                      onClick={() => {
                        const code = `version: '3.8'\nservices:\n  scanner-agent:\n    image: rizzolve/scanner-agent:latest\n    container_name: rizintel_scanner_agent\n    restart: always\n    environment:\n      - RIZINTEL_API_URL=http://host.docker.internal:8000\n      - RIZINTEL_ORGANIZATION_ID=${selectedOrg?.organization_id || 'ORG-RIZZOLVE-DEMO'}\n      - RIZINTEL_AGENT_ID=AGENT-YOUR-ID\n      - RIZINTEL_AGENT_TOKEN=agt_your_secret_token\n      - HEARTBEAT_INTERVAL_SEC=30\n    logging:\n      driver: "json-file"\n      options:\n        max-size: "20m"\n        max-file: "5"`;
                        navigator.clipboard?.writeText(code);
                        setCopiedSnippet('compose');
                        setTimeout(() => setCopiedSnippet(null), 2000);
                      }}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', border: '1px solid #CBD5E1', background: '#FFF', fontSize: '11.5px', fontWeight: '600', cursor: 'pointer', color: '#475569' }}
                    >
                      {copiedSnippet === 'compose' ? <><Check size={12} color="#10B981" /> Copied!</> : <><Copy size={12} /> Copy</>}
                    </button>
                  </div>
                  <pre style={{ margin: 0, padding: '14px', borderRadius: '10px', background: '#0F172A', color: '#E2E8F0', fontFamily: 'monospace', fontSize: '12px', overflowX: 'auto', lineHeight: '1.6' }}>
{`version: '3.8'
services:
  scanner-agent:
    image: rizzolve/scanner-agent:latest
    container_name: rizintel_scanner_agent
    restart: always
    environment:
      - RIZINTEL_API_URL=http://host.docker.internal:8000
      - RIZINTEL_ORGANIZATION_ID=${selectedOrg?.organization_id || 'ORG-RIZZOLVE-DEMO'}
      - RIZINTEL_AGENT_ID=AGENT-YOUR-ID
      - RIZINTEL_AGENT_TOKEN=agt_your_secret_token
      - HEARTBEAT_INTERVAL_SEC=30
    logging:
      driver: "json-file"
      options:
        max-size: "20m"
        max-file: "5"`}
                  </pre>
                </div>
              </div>
            )}

            {/* Tab 3: Environment Variables */}
            {guideTab === 'env' && (
              <div style={{ fontSize: '13px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', borderRadius: '8px', overflow: 'hidden', border: '1px solid var(--border-color, #E2E8F0)' }}>
                  <thead>
                    <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E8F0', textAlign: 'left', color: '#64748B', fontSize: '12px', fontWeight: '700' }}>
                      <th style={{ padding: '10px 14px' }}>Variable</th>
                      <th style={{ padding: '10px 14px' }}>Required</th>
                      <th style={{ padding: '10px 14px' }}>Description & Default</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr style={{ borderBottom: '1px solid #F1F5F9' }}>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: '700', color: '#4F46E5' }}>RIZINTEL_API_URL</td>
                      <td style={{ padding: '10px 14px', color: '#DC2626', fontWeight: '700' }}>Yes</td>
                      <td style={{ padding: '10px 14px', color: '#475569' }}>RizIntel backend endpoint URL (e.g. <code>http://127.0.0.1:8000</code>).</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #F1F5F9' }}>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: '700', color: '#4F46E5' }}>RIZINTEL_ORGANIZATION_ID</td>
                      <td style={{ padding: '10px 14px', color: '#DC2626', fontWeight: '700' }}>Yes</td>
                      <td style={{ padding: '10px 14px', color: '#475569' }}>Tenant identifier where the agent is authorized.</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #F1F5F9' }}>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: '700', color: '#4F46E5' }}>RIZINTEL_AGENT_ID</td>
                      <td style={{ padding: '10px 14px', color: '#DC2626', fontWeight: '700' }}>Yes</td>
                      <td style={{ padding: '10px 14px', color: '#475569' }}>Unique Agent ID generated at registration time.</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #F1F5F9' }}>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: '700', color: '#4F46E5' }}>RIZINTEL_AGENT_TOKEN</td>
                      <td style={{ padding: '10px 14px', color: '#DC2626', fontWeight: '700' }}>Yes</td>
                      <td style={{ padding: '10px 14px', color: '#475569' }}>Secret bearer token matching the agent's registration.</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid #F1F5F9' }}>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: '700', color: '#0F172A' }}>HEARTBEAT_INTERVAL_SEC</td>
                      <td style={{ padding: '10px 14px', color: '#64748B' }}>No</td>
                      <td style={{ padding: '10px 14px', color: '#475569' }}>Frequency of liveness heartbeats (default: <code>30</code>).</td>
                    </tr>
                    <tr>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: '700', color: '#0F172A' }}>LOG_LEVEL</td>
                      <td style={{ padding: '10px 14px', color: '#64748B' }}>No</td>
                      <td style={{ padding: '10px 14px', color: '#475569' }}>Output logging verbosity: <code>INFO</code>, <code>DEBUG</code>, <code>WARNING</code>.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            {/* Tab 4: Security & Architecture */}
            {guideTab === 'security' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '13.5px', color: 'var(--text-primary, #334155)', lineHeight: '1.55' }}>
                <div style={{ background: '#F0FDF4', border: '1px solid #BBF7D0', padding: '16px', borderRadius: '10px' }}>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: '700', color: '#166534' }}>
                    Zero-Knowledge Token Security
                  </h4>
                  <p style={{ margin: 0, color: '#14532D', fontSize: '13px' }}>
                    Agent secrets are hashed using SHA-256 with a unique salt prior to persistence. Plaintext tokens are never stored on the server and are only displayed once upon registration.
                  </p>
                </div>

                <div style={{ background: '#FEF3C7', border: '1px solid #FDE68A', padding: '16px', borderRadius: '10px' }}>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: '700', color: '#92400E' }}>
                    Immediate Revocation Enforcement
                  </h4>
                  <p style={{ margin: 0, color: '#78350F', fontSize: '13px' }}>
                    Revoking an agent in the UI permanently disables its credentials. Subsequent heartbeat requests or job ingestions will be rejected with HTTP 401 Unauthorized immediately.
                  </p>
                </div>

                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: '700', color: '#0F172A' }}>
                    Autonomous Scan Job Pipeline
                  </h4>
                  <p style={{ margin: 0, color: '#64748B', fontSize: '13px' }}>
                    When a scan run is initiated in RizIntel, active agents receive assigned targets, execute scanners in isolated environments, and stream normalized finding payloads over TLS directly into the deduplication pipeline.
                  </p>
                </div>
              </div>
            )}

            {/* Modal Footer */}
            <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid var(--border-color, #E2E8F0)', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setShowSetupGuideModal(false)}
                style={{
                  padding: '9px 20px',
                  borderRadius: '8px',
                  border: 'none',
                  background: '#4F46E5',
                  color: '#FFFFFF',
                  fontWeight: '600',
                  fontSize: '13.5px',
                  cursor: 'pointer'
                }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
