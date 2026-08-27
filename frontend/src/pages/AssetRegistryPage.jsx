import React, { useState, useEffect, useCallback } from 'react';
import { 
  Server, Plus, ShieldCheck, ShieldAlert, CheckCircle2, 
  XCircle, Filter, Activity, Globe, Lock, AlertTriangle,
  RefreshCw, Search, X, Clock, Eye, Check, ChevronLeft, ChevronRight,
  Database, Code, AlertCircle, Info, Copy
} from 'lucide-react';
import { getCurrentUser } from '../services/findingsService';
import { 
  getMyOrganizations, 
  getRegisteredAssets, 
  registerAsset, 
  updateAssetStatus,
  getScanRuns
} from '../services/workspaceService';

export default function AssetRegistryPage() {
  const currentUser = getCurrentUser();
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [assets, setAssets] = useState([]);
  const [scanRuns, setScanRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Search, Filter, Pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [envFilter, setEnvFilter] = useState('ALL');
  const [critFilter, setCritFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(6);

  // Modals & Drawers State
  const [showRegisterDrawer, setShowRegisterDrawer] = useState(false);
  const [registerFormError, setRegisterFormError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [confirmModal, setConfirmModal] = useState({ open: false, type: 'AUTHORIZE', asset: null });
  const [detailModal, setDetailModal] = useState({ open: false, asset: null });
  const [toast, setToast] = useState(null);

  // Register Form Data
  const [formData, setFormData] = useState({
    display_name: '',
    asset_type: 'Web Application',
    host: '',
    port: '',
    environment: 'production',
    criticality: 'HIGH',
    internet_facing: true,
    data_sensitivity: 'CONFIDENTIAL',
  });

  // Strict backend RBAC check: only SECURITY_LEAD or ADMIN can mutate assets
  const userRole = currentUser?.role || 'VIEWER';
  const isLeadOrAdmin = userRole === 'SECURITY_LEAD' || userRole === 'ADMIN';

  // Toast Helper
  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Keyboard Escape listener to close modals/drawers
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setShowRegisterDrawer(false);
        setConfirmModal({ open: false, type: 'AUTHORIZE', asset: null });
        setDetailModal({ open: false, asset: null });
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      let orgs = await getMyOrganizations().catch(() => []);
      if (!orgs || orgs.length === 0) {
        orgs = [{ organization_id: 'ORG-DEMO-001', display_name: 'RizIntel Demo Organization' }];
      }
      setOrganizations(orgs);
      
      const org = orgs[0];
      setSelectedOrg(org);
      
      const [assetList, runs] = await Promise.all([
        getRegisteredAssets(org.organization_id),
        getScanRuns(org.organization_id).catch(() => [])
      ]);
      
      setAssets(assetList || []);
      setScanRuns(runs || []);
    } catch (err) {
      console.error('Failed to load asset registry:', err);
      setError(err.message || 'Unable to load asset registry right now.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleOrgChange = async (orgId) => {
    const org = organizations.find(o => o.organization_id === orgId);
    if (!org) return;
    setSelectedOrg(org);
    try {
      setLoading(true);
      setError(null);
      const [assetList, runs] = await Promise.all([
        getRegisteredAssets(orgId).catch(() => []),
        getScanRuns(orgId).catch(() => [])
      ]);
      setAssets(assetList || []);
      setScanRuns(runs || []);
      setCurrentPage(1);
    } catch (err) {
      console.error('Error fetching assets for organization:', err);
      setError(err.message || 'Failed to retrieve assets for the selected organization.');
    } finally {
      setLoading(false);
    }
  };

  // Form Submission
  const handleRegisterSubmit = async (e) => {
    e.preventDefault();

    const trimmedName = (formData.display_name || '').trim();
    const trimmedHost = (formData.host || '').trim();

    if (!trimmedName) {
      setRegisterFormError('Asset Name is required.');
      return;
    }
    if (!trimmedHost) {
      setRegisterFormError('Host / Domain is required.');
      return;
    }

    const targetOrgId = selectedOrg?.organization_id || (organizations && organizations[0]?.organization_id) || 'ORG-DEMO-001';

    let parsedPort = null;
    if (formData.port !== '' && formData.port !== null && formData.port !== undefined) {
      parsedPort = parseInt(formData.port, 10);
      if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        setRegisterFormError('Port must be a valid number between 1 and 65535.');
        return;
      }
    }

    try {
      setIsSubmitting(true);
      setRegisterFormError(null);

      // Append asset_type to display_name or handle appropriately
      const payloadName = formData.asset_type ? `${trimmedName} (${formData.asset_type})` : trimmedName;

      const payload = {
        display_name: payloadName,
        host: trimmedHost,
        port: parsedPort,
        environment: formData.environment || 'staging',
        criticality: formData.criticality || 'HIGH',
        internet_facing: Boolean(formData.internet_facing),
        data_sensitivity: formData.data_sensitivity || 'CONFIDENTIAL',
      };

      await registerAsset(targetOrgId, payload);
      
      setShowRegisterDrawer(false);
      setFormData({
        display_name: '',
        asset_type: 'Web Application',
        host: '',
        port: '',
        environment: 'production',
        criticality: 'HIGH',
        internet_facing: true,
        data_sensitivity: 'CONFIDENTIAL',
      });

      showToast(`Asset "${trimmedName}" registered successfully with PENDING status.`);
      
      // Refresh assets list
      const updatedList = await getRegisteredAssets(targetOrgId).catch(() => []);
      setAssets(updatedList || []);
    } catch (err) {
      console.error('Registration failed:', err);
      if (err.message && (err.message.includes('already exists') || err.message.includes('409'))) {
        setRegisterFormError('An asset with this host and port is already registered in this organization.');
      } else {
        setRegisterFormError(err.message || 'Failed to register asset. Please check fields and try again.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  // Status Updates (Authorize / Disable)
  const handleExecuteStatusUpdate = async () => {
    const { asset, type } = confirmModal;
    if (!selectedOrg || !asset || !isLeadOrAdmin) return;

    const targetStatus = type === 'AUTHORIZE' ? 'AUTHORIZED' : 'DISABLED';
    
    try {
      setIsSubmitting(true);
      await updateAssetStatus(selectedOrg.organization_id, asset.asset_id, targetStatus);
      
      setConfirmModal({ open: false, type: 'AUTHORIZE', asset: null });
      showToast(`Asset "${asset.display_name}" is now ${targetStatus}.`);

      const updatedList = await getRegisteredAssets(selectedOrg.organization_id);
      setAssets(updatedList || []);
    } catch (err) {
      console.error('Status update error:', err);
      showToast(`Failed to update asset status: ${err.message}`, 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Last Scan Resolution
  const getLastScanForAsset = (assetId) => {
    if (!scanRuns || scanRuns.length === 0) return null;
    const runs = scanRuns
      .filter(r => r.asset_id === assetId && r.created_at)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    
    if (runs.length === 0) return null;
    
    const latest = runs[0];
    try {
      const d = new Date(latest.created_at);
      if (isNaN(d.getTime())) return null;
      return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) + 
        ', ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return null;
    }
  };

  // Derive Summary Counts
  const totalAssetsCount = assets.length;
  const authorizedCount = assets.filter(a => a.authorization_status === 'AUTHORIZED').length;
  const pendingCount = assets.filter(a => a.authorization_status === 'PENDING').length;
  const disabledCount = assets.filter(a => a.authorization_status === 'DISABLED').length;

  // Filtered Assets Computation
  const filteredAssets = assets.filter(asset => {
    const query = searchQuery.toLowerCase().trim();
    const nameMatch = (asset.display_name || '').toLowerCase().includes(query);
    const hostMatch = (asset.host || asset.normalized_host || '').toLowerCase().includes(query);
    const idMatch = (asset.asset_id || '').toLowerCase().includes(query);
    
    if (query && !nameMatch && !hostMatch && !idMatch) return false;
    if (statusFilter !== 'ALL' && asset.authorization_status !== statusFilter) return false;
    if (envFilter !== 'ALL' && asset.environment !== envFilter) return false;
    if (critFilter !== 'ALL' && asset.criticality !== critFilter) return false;
    
    return true;
  });

  // Pagination Math
  const totalPages = Math.ceil(filteredAssets.length / rowsPerPage) || 1;
  const paginatedAssets = filteredAssets.slice((currentPage - 1) * rowsPerPage, currentPage * rowsPerPage);

  // Helper for Status Badge Styling
  const renderStatusBadge = (status) => {
    switch (status) {
      case 'AUTHORIZED':
        return (
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            padding: '3px 10px',
            borderRadius: '12px',
            fontSize: '11px',
            fontWeight: '700',
            background: '#DCFCE7',
            color: '#15803D',
            border: '1px solid #BBF7D0',
            letterSpacing: '0.3px'
          }}>
            <CheckCircle2 size={12} /> AUTHORIZED
          </span>
        );
      case 'PENDING':
        return (
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            padding: '3px 10px',
            borderRadius: '12px',
            fontSize: '11px',
            fontWeight: '700',
            background: '#FEF3C7',
            color: '#D97706',
            border: '1px solid #FDE68A',
            letterSpacing: '0.3px'
          }}>
            <Clock size={12} /> PENDING
          </span>
        );
      case 'DISABLED':
        return (
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            padding: '3px 10px',
            borderRadius: '12px',
            fontSize: '11px',
            fontWeight: '700',
            background: '#F1F5F9',
            color: '#64748B',
            border: '1px solid #E2E8F0',
            letterSpacing: '0.3px'
          }}>
            <XCircle size={12} /> DISABLED
          </span>
        );
      default:
        return (
          <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: '700', background: '#F1F5F9', color: '#64748B' }}>
            {status}
          </span>
        );
    }
  };

  // Helper for Criticality Badge Styling
  const renderCriticalityBadge = (crit) => {
    let bg = '#F1F5F9', color = '#475569', border = '#E2E8F0';
    if (crit === 'CRITICAL') { bg = '#FEF2F2'; color = '#DC2626'; border = '#FCA5A5'; }
    else if (crit === 'HIGH') { bg = '#FFF7ED'; color = '#EA580C'; border = '#FED7AA'; }
    else if (crit === 'MEDIUM') { bg = '#FEFCE8'; color = '#CA8A04'; border = '#FEF08A'; }
    else if (crit === 'LOW') { bg = '#F0FDF4'; color = '#16A34A'; border = '#BBF7D0'; }

    return (
      <span style={{
        padding: '2px 8px',
        borderRadius: '6px',
        fontSize: '11px',
        fontWeight: '700',
        background: bg,
        color: color,
        border: `1px solid ${border}`
      }}>
        {crit}
      </span>
    );
  };

  return (
    <div style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflowX: 'hidden', padding: '4px 0 24px', fontFamily: 'var(--font-sans, system-ui, -apple-system, sans-serif)' }}>
      {/* Toast Floating Notification */}
      {toast && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          zIndex: 9999,
          background: toast.type === 'error' ? '#FEF2F2' : '#F0FDF4',
          border: `1px solid ${toast.type === 'error' ? '#FCA5A5' : '#86EFAC'}`,
          color: toast.type === 'error' ? '#991B1B' : '#166534',
          padding: '12px 18px',
          borderRadius: '10px',
          boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          fontSize: '13.5px',
          fontWeight: '600',
          animation: 'fadeIn 0.2s ease-in-out'
        }}>
          {toast.type === 'error' ? <AlertCircle size={18} color="#DC2626" /> : <CheckCircle2 size={18} color="#16A34A" />}
          <span>{toast.message}</span>
        </div>
      )}

      {/* 1. Page Header */}
      <div style={{ 
        display: 'flex', 
        flexWrap: 'wrap',
        alignItems: 'center', 
        justifyContent: 'space-between', 
        gap: '16px',
        marginBottom: '24px',
        paddingBottom: '16px',
        borderBottom: '1px solid var(--border-color, #E2E8F0)' 
      }}>
        <div style={{ minWidth: 0 }}>
          <h1 style={{ fontSize: '24px', fontWeight: '700', margin: '0 0 4px 0', color: 'var(--text-primary, #0F172A)', letterSpacing: '-0.3px' }}>
            Asset Registry
          </h1>
          <p style={{ fontSize: '13.5px', color: 'var(--text-secondary, #64748B)', margin: '0 0 8px 0' }}>
            Manage approved applications, APIs, hosts and endpoints available for security scanning.
          </p>

          {/* Role Badge (Subtle Read-Only badge if Viewer / Analyst) */}
          {!isLeadOrAdmin && (
            <div style={{ 
              display: 'inline-flex', 
              alignItems: 'center', 
              gap: '6px', 
              fontSize: '12px', 
              fontWeight: '600',
              color: '#6366F1', 
              background: '#EEF2FF', 
              border: '1px solid #C7D2FE',
              padding: '4px 10px', 
              borderRadius: '6px' 
            }}>
              <Lock size={13} />
              <span>Read-Only Access</span>
            </div>
          )}
        </div>

        {/* Top Right Controls: Organization Selector + Register Button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {organizations.length > 0 && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: 'var(--bg-card, #FFFFFF)',
              border: '1px solid var(--border-color, #CBD5E1)',
              padding: '6px 12px',
              borderRadius: '10px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
            }}>
              <Server size={16} color="#6366F1" />
              <select 
                value={selectedOrg?.organization_id || ''} 
                onChange={(e) => handleOrgChange(e.target.value)}
                style={{
                  border: 'none',
                  background: 'transparent',
                  fontSize: '13.5px',
                  fontWeight: '600',
                  color: 'var(--text-primary, #1E293B)',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                {organizations.map(o => (
                  <option key={o.organization_id} value={o.organization_id}>{o.display_name}</option>
                ))}
              </select>
            </div>
          )}

          {isLeadOrAdmin && (
            <button
              id="register-asset-btn"
              onClick={() => setShowRegisterDrawer(true)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                background: '#4F46E5',
                color: '#FFFFFF',
                padding: '9px 18px',
                borderRadius: '10px',
                border: 'none',
                fontSize: '13.5px',
                fontWeight: '600',
                cursor: 'pointer',
                boxShadow: '0 2px 4px rgba(79, 70, 229, 0.25)',
                transition: 'background 0.15s ease'
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = '#4338CA'}
              onMouseLeave={(e) => e.currentTarget.style.background = '#4F46E5'}
            >
              <Plus size={16} />
              <span>Register Asset</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Summary Cards Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', 
        gap: '16px', 
        marginBottom: '24px' 
      }}>
        {/* Card 1: Total Assets */}
        <div style={{
          background: 'var(--bg-card, #FFFFFF)',
          borderRadius: '12px',
          border: '1px solid var(--border-color, #E2E8F0)',
          padding: '18px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
        }}>
          <div style={{ background: 'var(--bg-lavender, #F5F3FF)', color: '#7C3AED', padding: '12px', borderRadius: '12px' }}>
            <Server size={22} />
          </div>
          <div>
            <div style={{ fontSize: '26px', fontWeight: '800', color: 'var(--text-primary, #0F172A)', lineHeight: 1 }}>
              {totalAssetsCount}
            </div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #334155)', marginTop: '4px' }}>Total Assets</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted, #94A3B8)' }}>All registered assets</div>
          </div>
        </div>

        {/* Card 2: Authorized */}
        <div style={{
          background: 'var(--bg-card, #FFFFFF)',
          borderRadius: '12px',
          border: '1px solid var(--border-color, #E2E8F0)',
          padding: '18px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
        }}>
          <div style={{ background: 'rgba(16, 185, 129, 0.12)', color: '#10B981', padding: '12px', borderRadius: '12px' }}>
            <CheckCircle2 size={22} />
          </div>
          <div>
            <div style={{ fontSize: '26px', fontWeight: '800', color: 'var(--text-primary, #0F172A)', lineHeight: 1 }}>
              {authorizedCount}
            </div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #334155)', marginTop: '4px' }}>Authorized</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted, #94A3B8)' }}>Ready for scanning</div>
          </div>
        </div>

        {/* Card 3: Pending Approval */}
        <div style={{
          background: 'var(--bg-card, #FFFFFF)',
          borderRadius: '12px',
          border: '1px solid var(--border-color, #E2E8F0)',
          padding: '18px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
        }}>
          <div style={{ background: 'rgba(245, 158, 11, 0.12)', color: '#D97706', padding: '12px', borderRadius: '12px' }}>
            <Clock size={22} />
          </div>
          <div>
            <div style={{ fontSize: '26px', fontWeight: '800', color: 'var(--text-primary, #0F172A)', lineHeight: 1 }}>
              {pendingCount}
            </div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #334155)', marginTop: '4px' }}>Pending Approval</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted, #94A3B8)' }}>Awaiting authorization</div>
          </div>
        </div>

        {/* Card 4: Disabled */}
        <div style={{
          background: 'var(--bg-card, #FFFFFF)',
          borderRadius: '12px',
          border: '1px solid var(--border-color, #E2E8F0)',
          padding: '18px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
        }}>
          <div style={{ background: 'rgba(239, 68, 68, 0.12)', color: '#EF4444', padding: '12px', borderRadius: '12px' }}>
            <XCircle size={22} />
          </div>
          <div>
            <div style={{ fontSize: '26px', fontWeight: '800', color: 'var(--text-primary, #0F172A)', lineHeight: 1 }}>
              {disabledCount}
            </div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary, #334155)', marginTop: '4px' }}>Disabled</div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted, #94A3B8)' }}>Scanning disabled</div>
          </div>
        </div>
      </div>

      {/* 3. Search & Filter Bar */}
      <div style={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        gap: '12px',
        marginBottom: '20px',
        background: 'var(--bg-card, #FFFFFF)',
        padding: '14px 18px',
        borderRadius: '12px',
        border: '1px solid var(--border-color, #E2E8F0)'
      }}>
        {/* Search Input */}
        <div style={{ position: 'relative', flex: '1 1 240px', minWidth: '200px' }}>
          <Search size={16} color="#94A3B8" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
          <input 
            type="text"
            placeholder="Search by asset name or host..."
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
            style={{
              width: '100%',
              padding: '8px 12px 8px 36px',
              borderRadius: '8px',
              border: '1px solid var(--border-color, #CBD5E1)',
              background: 'var(--bg-input, #FFFFFF)',
              color: 'var(--text-primary, #0F172A)',
              fontSize: '13.5px',
              outline: 'none',
              boxSizing: 'border-box'
            }}
          />
        </div>

        {/* Filter Dropdowns */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary, #64748B)' }}>Status</span>
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }}
              style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-input, #FFF)', fontSize: '13px', color: 'var(--text-primary, #334155)' }}
            >
              <option value="ALL">All Statuses</option>
              <option value="AUTHORIZED">Authorized</option>
              <option value="PENDING">Pending</option>
              <option value="DISABLED">Disabled</option>
            </select>
          </div>

          {/* Environment Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary, #64748B)' }}>Environment</span>
            <select
              value={envFilter}
              onChange={(e) => { setEnvFilter(e.target.value); setCurrentPage(1); }}
              style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-input, #FFF)', fontSize: '13px', color: 'var(--text-primary, #334155)' }}
            >
              <option value="ALL">All Environments</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="lab">Lab</option>
            </select>
          </div>

          {/* Criticality Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary, #64748B)' }}>Criticality</span>
            <select
              value={critFilter}
              onChange={(e) => { setCritFilter(e.target.value); setCurrentPage(1); }}
              style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-input, #FFF)', fontSize: '13px', color: 'var(--text-primary, #334155)' }}
            >
              <option value="ALL">All Criticality</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Refresh Button */}
          <button
            type="button"
            onClick={loadData}
            title="Refresh assets data"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 12px',
              borderRadius: '8px',
              border: '1px solid var(--border-color, #CBD5E1)',
              background: 'var(--bg-card, #FFF)',
              color: 'var(--text-primary, #475569)',
              fontSize: '13px',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 4. Main Body: Loading State / Error State / Asset Cards / Empty State */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted, #64748B)' }}>
          <Activity className="animate-spin" size={32} style={{ margin: '0 auto 12px auto', color: '#4F46E5' }} />
          <p style={{ fontSize: '14px', fontWeight: '600', margin: 0 }}>Loading assets...</p>
        </div>
      ) : error ? (
        /* Error State Banner */
        <div style={{
          background: '#FEF2F2',
          border: '1px solid #FCA5A5',
          borderRadius: '12px',
          padding: '24px',
          textAlign: 'center',
          color: '#991B1B'
        }}>
          <AlertTriangle size={36} style={{ margin: '0 auto 12px auto', color: '#DC2626' }} />
          <h3 style={{ fontSize: '16px', fontWeight: '700', margin: '0 0 6px 0' }}>Unable to load assets</h3>
          <p style={{ fontSize: '13.5px', color: '#B91C1C', margin: '0 0 16px 0' }}>We couldn't retrieve the Asset Registry right now.</p>
          <button
            type="button"
            onClick={loadData}
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: '1px solid #FCA5A5',
              background: '#FFF',
              color: '#991B1B',
              fontWeight: '700',
              fontSize: '13.5px',
              cursor: 'pointer'
            }}
          >
            Retry
          </button>
        </div>
      ) : assets.length === 0 ? (
        /* Zero Assets Empty State */
        <div style={{
          background: 'var(--bg-card, #FFFFFF)',
          borderRadius: '12px',
          border: '1px solid var(--border-color, #E2E8F0)',
          padding: '60px 24px',
          textAlign: 'center'
        }}>
          <Server size={44} color="#94A3B8" style={{ margin: '0 auto 16px auto', opacity: 0.7 }} />
          <h3 style={{ fontSize: '18px', fontWeight: '700', margin: '0 0 8px 0', color: 'var(--text-primary, #0F172A)' }}>No assets registered yet</h3>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary, #64748B)', margin: '0 0 6px 0', maxWidth: '480px', marginLeft: 'auto', marginRight: 'auto', fontWeight: '500' }}>
            Assets must be registered before security scan runs can be created.
          </p>
          <p style={{ fontSize: '13px', color: 'var(--text-muted, #64748B)', margin: '0 0 24px 0', opacity: 0.9 }}>
            Asset registration requires Security Lead or Administrator access.
          </p>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px', flexWrap: 'wrap' }}>
            {isLeadOrAdmin && (
              <button
                type="button"
                id="empty-register-asset-btn"
                onClick={() => setShowRegisterDrawer(true)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: '#4F46E5',
                  color: '#FFF',
                  padding: '10px 20px',
                  borderRadius: '8px',
                  border: 'none',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                <Plus size={16} /> Register Asset
              </button>
            )}
            <button
              type="button"
              onClick={loadData}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                background: 'var(--bg-surface-elevated, #FFF)',
                color: 'var(--text-primary, #475569)',
                border: '1px solid var(--border-color, #CBD5E1)',
                padding: '9px 18px',
                borderRadius: '8px',
                fontSize: '13.5px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              <RefreshCw size={14} /> Refresh Assets
            </button>
          </div>
        </div>
      ) : filteredAssets.length === 0 ? (
        /* Search/Filter No Match State */
        <div style={{
          background: 'var(--bg-card, #FFFFFF)',
          borderRadius: '12px',
          border: '1px solid var(--border-color, #E2E8F0)',
          padding: '48px 24px',
          textAlign: 'center'
        }}>
          <Filter size={36} color="#94A3B8" style={{ margin: '0 auto 12px auto' }} />
          <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '0 0 4px 0', color: 'var(--text-primary, #0F172A)' }}>No assets match your filters.</h3>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary, #64748B)', margin: '0 0 16px 0' }}>Try adjusting your search query or filter criteria.</p>
          <button
            type="button"
            onClick={() => { setSearchQuery(''); setStatusFilter('ALL'); setEnvFilter('ALL'); setCritFilter('ALL'); }}
            style={{ padding: '6px 14px', borderRadius: '6px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-surface-elevated, #FFF)', color: 'var(--text-primary, #334155)', fontSize: '13px', cursor: 'pointer' }}
          >
            Clear Filters
          </button>
        </div>
      ) : (
        /* Asset Cards Grid View */
        <>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            gap: '16px',
            marginBottom: '20px'
          }}>
            {paginatedAssets.map(asset => {
              const lastScan = getLastScanForAsset(asset.asset_id);
              
              return (
                <div key={asset.asset_id} style={{
                  background: 'var(--bg-card, #FFFFFF)',
                  borderRadius: '12px',
                  border: '1px solid var(--border-color, #E2E8F0)',
                  padding: '20px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '16px',
                  transition: 'border-color 0.15s ease, box-shadow 0.15s ease'
                }}>
                  {/* Card Header: Icon + Name + Status Badge */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px', marginBottom: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ 
                          background: 'var(--bg-lavender, #EEF2FF)', 
                          color: '#4F46E5', 
                          padding: '10px', 
                          borderRadius: '10px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center'
                        }}>
                          <Server size={18} />
                        </div>
                        <div>
                          <h3 style={{ fontSize: '15px', fontWeight: '700', margin: 0, color: 'var(--text-primary, #0F172A)', lineHeight: 1.3 }}>
                            {asset.display_name}
                          </h3>
                        </div>
                      </div>
                      <div>
                        {renderStatusBadge(asset.authorization_status)}
                      </div>
                    </div>

                    {/* Host & Port Subtitle */}
                    <div style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--text-secondary, #475569)', margin: '4px 0 14px 0', wordBreak: 'break-all' }}>
                      {asset.normalized_host || asset.host}
                      {asset.port ? <span style={{ color: '#818CF8' }}>:{asset.port}</span> : ''}
                    </div>

                    {/* Metadata Grid Badges */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                      {/* Environment Tag */}
                      <span style={{
                        fontSize: '11px',
                        fontWeight: '600',
                        color: 'var(--text-secondary, #475569)',
                        background: 'var(--bg-surface-elevated, #F1F5F9)',
                        padding: '3px 8px',
                        borderRadius: '6px',
                        textTransform: 'capitalize'
                      }}>
                        {asset.environment}
                      </span>

                      {/* Criticality */}
                      {renderCriticalityBadge(asset.criticality)}

                      {/* Exposure Tag */}
                      {asset.internet_facing ? (
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '3px',
                          fontSize: '11px',
                          fontWeight: '600',
                          color: '#3B82F6',
                          background: 'rgba(59, 130, 246, 0.12)',
                          border: '1px solid rgba(59, 130, 246, 0.3)',
                          padding: '2px 8px',
                          borderRadius: '6px'
                        }}>
                          <Globe size={11} /> Internet-Facing
                        </span>
                      ) : (
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '3px',
                          fontSize: '11px',
                          fontWeight: '600',
                          color: 'var(--text-muted, #64748B)',
                          background: 'var(--bg-surface-elevated, #F8FAFC)',
                          border: '1px solid var(--border-color, #E2E8F0)',
                          padding: '2px 8px',
                          borderRadius: '6px'
                        }}>
                          <Lock size={11} /> Internal
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Card Footer: Last Scan & Actions */}
                  <div style={{
                    paddingTop: '12px',
                    borderTop: '1px solid var(--border-color, #F1F5F9)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px'
                  }}>
                    <div style={{ fontSize: '11.5px', color: 'var(--text-secondary, #64748B)' }}>
                      <span style={{ display: 'block', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.4px', fontWeight: '700', color: 'var(--text-muted, #94A3B8)' }}>Last Scan</span>
                      <span>{lastScan || '—'}</span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {/* View Details */}
                      <button
                        type="button"
                        onClick={() => setDetailModal({ open: true, asset })}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          background: 'var(--bg-surface-elevated, #F8FAFC)',
                          border: '1px solid var(--border-color, #E2E8F0)',
                          color: 'var(--text-primary, #475569)',
                          padding: '5px 10px',
                          borderRadius: '6px',
                          fontSize: '12px',
                          fontWeight: '600',
                          cursor: 'pointer'
                        }}
                      >
                        <Eye size={13} /> View Details
                      </button>

                      {/* Authorize / Disable Buttons for Lead/Admin */}
                      {isLeadOrAdmin && asset.authorization_status === 'PENDING' && (
                        <button
                          type="button"
                          className="auth-btn-authorize"
                          onClick={() => setConfirmModal({ open: true, type: 'AUTHORIZE', asset })}
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            background: '#DCFCE7',
                            border: '1px solid #16A34A',
                            color: '#15803D',
                            padding: '5px 12px',
                            borderRadius: '6px',
                            fontSize: '12px',
                            fontWeight: '700',
                            cursor: 'pointer'
                          }}
                        >
                          Authorize
                        </button>
                      )}

                      {isLeadOrAdmin && asset.authorization_status === 'AUTHORIZED' && (
                        <button
                          type="button"
                          className="auth-btn-disable"
                          onClick={() => setConfirmModal({ open: true, type: 'DISABLE', asset })}
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            background: 'var(--bg-surface-elevated, #FFF)',
                            border: '1px solid var(--border-color, #CBD5E1)',
                            color: 'var(--text-secondary, #64748B)',
                            padding: '5px 10px',
                            borderRadius: '6px',
                            fontSize: '12px',
                            fontWeight: '600',
                            cursor: 'pointer'
                          }}
                        >
                          Disable
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Pagination Toolbar */}
          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            background: 'var(--bg-card, #FFFFFF)',
            padding: '12px 18px',
            borderRadius: '10px',
            border: '1px solid var(--border-color, #E2E8F0)',
            fontSize: '13px',
            color: 'var(--text-secondary, #64748B)'
          }}>
            <div>
              Showing {((currentPage - 1) * rowsPerPage) + 1} to {Math.min(currentPage * rowsPerPage, filteredAssets.length)} of {filteredAssets.length} assets
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {/* Pagination Controls */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <button
                  type="button"
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  style={{
                    padding: '4px 8px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color, #CBD5E1)',
                    background: 'var(--bg-input, #FFF)',
                    color: 'var(--text-primary, #0F172A)',
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                    opacity: currentPage === 1 ? 0.5 : 1
                  }}
                >
                  <ChevronLeft size={16} />
                </button>

                {Array.from({ length: totalPages }, (_, i) => i + 1).map(pageNum => (
                  <button
                    key={pageNum}
                    type="button"
                    onClick={() => setCurrentPage(pageNum)}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      border: pageNum === currentPage ? '1px solid #4F46E5' : '1px solid var(--border-color, #CBD5E1)',
                      background: pageNum === currentPage ? 'var(--bg-lavender, #EEF2FF)' : 'var(--bg-input, #FFF)',
                      color: pageNum === currentPage ? '#818CF8' : 'var(--text-primary, #334155)',
                      fontWeight: pageNum === currentPage ? '700' : '500',
                      cursor: 'pointer'
                    }}
                  >
                    {pageNum}
                  </button>
                ))}

                <button
                  type="button"
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  style={{
                    padding: '4px 8px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color, #CBD5E1)',
                    background: 'var(--bg-input, #FFF)',
                    color: 'var(--text-primary, #0F172A)',
                    cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                    opacity: currentPage === totalPages ? 0.5 : 1
                  }}
                >
                  <ChevronRight size={16} />
                </button>
              </div>

              {/* Rows Per Page */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>Rows per page:</span>
                <select
                  value={rowsPerPage}
                  onChange={(e) => { setRowsPerPage(Number(e.target.value)); setCurrentPage(1); }}
                  style={{ padding: '4px 8px', borderRadius: '6px', border: '1px solid var(--border-color, #CBD5E1)', background: 'var(--bg-input, #FFF)', color: 'var(--text-primary, #0F172A)' }}
                >
                  <option value={6}>6</option>
                  <option value={12}>12</option>
                  <option value={24}>24</option>
                </select>
              </div>
            </div>
          </div>
        </>
      )}

      {/* 5. Register Asset Slide-over Drawer / Modal */}
      {showRegisterDrawer && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 23, 42, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          zIndex: 1000,
          animation: 'fadeIn 0.15s ease-out'
        }}>
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            width: '100%',
            maxWidth: '520px',
            height: '100%',
            boxShadow: '-10px 0 25px -5px rgba(0,0,0,0.15)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            padding: '28px',
            boxSizing: 'border-box',
            overflowY: 'auto'
          }}>
            <div>
              {/* Drawer Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', paddingBottom: '14px', borderBottom: '1px solid #E2E8F0' }}>
                <div>
                  <h2 style={{ fontSize: '20px', fontWeight: '700', margin: 0, color: '#0F172A' }}>Register Asset</h2>
                  <p style={{ fontSize: '13px', color: '#64748B', margin: '2px 0 0 0' }}>Add a new application, API, host or endpoint.</p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowRegisterDrawer(false)}
                  style={{ background: 'none', border: 'none', color: '#64748B', cursor: 'pointer', padding: '6px' }}
                >
                  <X size={20} />
                </button>
              </div>

              {/* Form Error Message */}
              {registerFormError && (
                <div style={{
                  background: '#FEF2F2',
                  border: '1px solid #FCA5A5',
                  color: '#991B1B',
                  padding: '12px 14px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  marginBottom: '18px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <AlertCircle size={16} color="#DC2626" />
                  <span>{registerFormError}</span>
                </div>
              )}

              {/* Form Fields */}
              <form id="register-asset-form" onSubmit={handleRegisterSubmit}>
                {/* Asset Name */}
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                    Asset Name <span style={{ color: '#DC2626' }}>*</span>
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Payments API"
                    value={formData.display_name}
                    onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', outline: 'none', boxSizing: 'border-box' }}
                  />
                </div>

                {/* Asset Type */}
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                    Asset Type <span style={{ color: '#DC2626' }}>*</span>
                  </label>
                  <select
                    value={formData.asset_type}
                    onChange={(e) => setFormData({ ...formData, asset_type: e.target.value })}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', outline: 'none', background: '#FFF', boxSizing: 'border-box' }}
                  >
                    <option value="Web Application">Web Application</option>
                    <option value="API">API</option>
                    <option value="Host / Infrastructure">Host / Infrastructure</option>
                    <option value="IP Endpoint">IP Endpoint</option>
                  </select>
                </div>

                {/* Host & Port Row */}
                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px', marginBottom: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                      Host / Domain <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. api.example.com"
                      value={formData.host}
                      onChange={(e) => setFormData({ ...formData, host: e.target.value })}
                      style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', outline: 'none', boxSizing: 'border-box' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                      Port
                    </label>
                    <input
                      type="number"
                      placeholder="e.g. 443"
                      value={formData.port}
                      onChange={(e) => setFormData({ ...formData, port: e.target.value })}
                      style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', outline: 'none', boxSizing: 'border-box' }}
                    />
                  </div>
                </div>

                {/* Environment & Criticality Row */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                      Environment <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <select
                      value={formData.environment}
                      onChange={(e) => setFormData({ ...formData, environment: e.target.value })}
                      style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', background: '#FFF', outline: 'none', boxSizing: 'border-box' }}
                    >
                      <option value="production">Production</option>
                      <option value="staging">Staging</option>
                      <option value="development">Development</option>
                      <option value="lab">Lab</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                      Business Criticality <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <select
                      value={formData.criticality}
                      onChange={(e) => setFormData({ ...formData, criticality: e.target.value })}
                      style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', background: '#FFF', outline: 'none', boxSizing: 'border-box' }}
                    >
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>
                </div>

                {/* Exposure & Sensitivity Row */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '20px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                      Network Exposure <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <select
                      value={formData.internet_facing ? 'true' : 'false'}
                      onChange={(e) => setFormData({ ...formData, internet_facing: e.target.value === 'true' })}
                      style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', background: '#FFF', outline: 'none', boxSizing: 'border-box' }}
                    >
                      <option value="true">Internet-Facing</option>
                      <option value="false">Internal</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                      Data Sensitivity <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <select
                      value={formData.data_sensitivity}
                      onChange={(e) => setFormData({ ...formData, data_sensitivity: e.target.value })}
                      style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '14px', background: '#FFF', outline: 'none', boxSizing: 'border-box' }}
                    >
                      <option value="RESTRICTED">Restricted</option>
                      <option value="CONFIDENTIAL">Confidential</option>
                      <option value="INTERNAL">Internal</option>
                      <option value="PUBLIC">Public</option>
                    </select>
                  </div>
                </div>

                {/* Info Callout Box */}
                <div style={{
                  background: '#EEF2FF',
                  border: '1px solid #C7D2FE',
                  borderRadius: '8px',
                  padding: '12px 14px',
                  fontSize: '12.5px',
                  color: '#4338CA',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                  marginBottom: '24px'
                }}>
                  <Info size={16} color="#4F46E5" style={{ flexShrink: 0, marginTop: '2px' }} />
                  <span>
                    New assets will be created with status <strong style={{ background: '#E0E7FF', padding: '1px 5px', borderRadius: '4px' }}>PENDING</strong> and require authorization before scanning.
                  </span>
                </div>

                {/* Footer Action Buttons */}
                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E2E8F0' }}>
                  <button
                    type="button"
                    onClick={() => setShowRegisterDrawer(false)}
                    style={{ padding: '9px 18px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', color: '#475569', fontSize: '13.5px', fontWeight: '600', cursor: 'pointer' }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    style={{
                      padding: '9px 20px',
                      borderRadius: '8px',
                      border: 'none',
                      background: '#4F46E5',
                      color: '#FFF',
                      fontSize: '13.5px',
                      fontWeight: '600',
                      cursor: isSubmitting ? 'not-allowed' : 'pointer',
                      opacity: isSubmitting ? 0.7 : 1
                    }}
                  >
                    {isSubmitting ? 'Registering...' : 'Register Asset'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* 6. Authorize / Disable Confirmation Modal */}
      {confirmModal.open && confirmModal.asset && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(15, 23, 42, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100
        }}>
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            borderRadius: '14px',
            padding: '24px',
            width: '100%',
            maxWidth: '460px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.15)'
          }}>
            <h3 style={{ fontSize: '18px', fontWeight: '700', marginTop: 0, marginBottom: '8px', color: '#0F172A' }}>
              {confirmModal.type === 'AUTHORIZE' ? 'Authorize Asset' : 'Disable Asset'}
            </h3>

            <p style={{ fontSize: '13.5px', color: '#475569', lineHeight: 1.5, margin: '0 0 16px 0' }}>
              {confirmModal.type === 'AUTHORIZE' 
                ? 'Authorize this asset for security scanning? Once authorized, this asset can be selected for security scan runs.'
                : 'Disable this asset? Disabling halts future scan runs against this target while preserving historical security findings.'
              }
            </p>

            <div style={{ background: '#F8FAFC', padding: '12px 14px', borderRadius: '8px', border: '1px solid #E2E8F0', marginBottom: '20px' }}>
              <div style={{ fontSize: '13.5px', fontWeight: '700', color: '#0F172A' }}>{confirmModal.asset.display_name}</div>
              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: '#64748B', marginTop: '2px' }}>
                {confirmModal.asset.normalized_host || confirmModal.asset.host}{confirmModal.asset.port ? `:${confirmModal.asset.port}` : ''}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setConfirmModal({ open: false, type: 'AUTHORIZE', asset: null })}
                style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', color: '#475569', fontWeight: '600', cursor: 'pointer' }}
              >
                Cancel
              </button>

              <button
                type="button"
                onClick={handleExecuteStatusUpdate}
                disabled={isSubmitting}
                style={{
                  padding: '8px 18px',
                  borderRadius: '8px',
                  border: 'none',
                  background: confirmModal.type === 'AUTHORIZE' ? '#16A34A' : '#DC2626',
                  color: '#FFF',
                  fontWeight: '700',
                  fontSize: '13.5px',
                  cursor: isSubmitting ? 'not-allowed' : 'pointer'
                }}
              >
                {isSubmitting ? 'Updating...' : (confirmModal.type === 'AUTHORIZE' ? 'Authorize Asset' : 'Disable Asset')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 7. Asset Detail Drawer / Modal */}
      {detailModal.open && detailModal.asset && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(15, 23, 42, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100
        }}>
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            borderRadius: '14px',
            padding: '28px',
            width: '100%',
            maxWidth: '560px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.15)',
            maxHeight: '90vh',
            overflowY: 'auto'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px', marginBottom: '16px' }}>
              <div>
                <h2 style={{ fontSize: '18px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                  Asset Details
                </h2>
                <div style={{ fontSize: '13px', color: '#64748B', marginTop: '2px' }}>{detailModal.asset.display_name}</div>
              </div>
              <button
                type="button"
                onClick={() => setDetailModal({ open: false, asset: null })}
                style={{ background: 'none', border: 'none', color: '#64748B', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Scan Readiness Status Header Box */}
            <div style={{
              background: detailModal.asset.authorization_status === 'AUTHORIZED' ? '#F0FDF4' : detailModal.asset.authorization_status === 'PENDING' ? '#FEFCE8' : '#F8FAFC',
              border: `1px solid ${detailModal.asset.authorization_status === 'AUTHORIZED' ? '#BBF7D0' : detailModal.asset.authorization_status === 'PENDING' ? '#FEF08A' : '#E2E8F0'}`,
              borderRadius: '10px',
              padding: '12px 16px',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {detailModal.asset.authorization_status === 'AUTHORIZED' ? (
                  <CheckCircle2 size={20} color="#16A34A" />
                ) : detailModal.asset.authorization_status === 'PENDING' ? (
                  <Clock size={20} color="#CA8A04" />
                ) : (
                  <XCircle size={20} color="#64748B" />
                )}
                <div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: '#0F172A' }}>
                    {detailModal.asset.authorization_status === 'AUTHORIZED' 
                      ? 'Ready for Scanning' 
                      : detailModal.asset.authorization_status === 'PENDING' 
                        ? 'Awaiting Authorization' 
                        : 'Scanning Disabled'
                    }
                  </div>
                  <div style={{ fontSize: '11.5px', color: '#64748B' }}>
                    {detailModal.asset.authorization_status === 'AUTHORIZED' 
                      ? 'This asset can be selected for security scan runs.' 
                      : detailModal.asset.authorization_status === 'PENDING'
                        ? 'Requires Security Lead authorization before launching scan runs.'
                        : 'This asset is currently disabled and excluded from scan target selection.'
                    }
                  </div>
                </div>
              </div>
              {renderStatusBadge(detailModal.asset.authorization_status)}
            </div>

            {/* Metadata Table Details */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', fontSize: '13px', marginBottom: '24px' }}>
              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Asset ID</span>
                <span style={{ fontFamily: 'monospace', fontWeight: '600', color: '#4F46E5' }}>{detailModal.asset.asset_id}</span>
              </div>

              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Host & Port</span>
                <span style={{ fontFamily: 'monospace', color: '#334155' }}>
                  {detailModal.asset.normalized_host || detailModal.asset.host}{detailModal.asset.port ? `:${detailModal.asset.port}` : ''}
                </span>
              </div>

              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Environment</span>
                <span style={{ textTransform: 'capitalize', color: '#334155' }}>{detailModal.asset.environment}</span>
              </div>

              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Business Criticality</span>
                {renderCriticalityBadge(detailModal.asset.criticality)}
              </div>

              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Network Exposure</span>
                <span style={{ color: '#334155' }}>{detailModal.asset.internet_facing ? 'Internet-Facing' : 'Internal'}</span>
              </div>

              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Data Sensitivity</span>
                <span style={{ color: '#334155' }}>{detailModal.asset.data_sensitivity}</span>
              </div>

              {detailModal.asset.created_at && (
                <div>
                  <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Registered Date</span>
                  <span style={{ color: '#334155' }}>{new Date(detailModal.asset.created_at).toLocaleString()}</span>
                </div>
              )}

              <div>
                <span style={{ display: 'block', fontSize: '11px', fontWeight: '700', color: '#94A3B8', textTransform: 'uppercase' }}>Last Scan</span>
                <span style={{ color: '#334155' }}>{getLastScanForAsset(detailModal.asset.asset_id) || '— No scans recorded'}</span>
              </div>
            </div>

            {/* Footer Buttons */}
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E2E8F0' }}>
              <button
                type="button"
                onClick={() => setDetailModal({ open: false, asset: null })}
                style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', color: '#475569', fontWeight: '600', cursor: 'pointer' }}
              >
                Close
              </button>

              {isLeadOrAdmin && detailModal.asset.authorization_status === 'PENDING' && (
                <button
                  type="button"
                  onClick={() => {
                    const target = detailModal.asset;
                    setDetailModal({ open: false, asset: null });
                    setConfirmModal({ open: true, type: 'AUTHORIZE', asset: target });
                  }}
                  style={{ padding: '8px 16px', borderRadius: '8px', border: 'none', background: '#16A34A', color: '#FFF', fontWeight: '700', cursor: 'pointer' }}
                >
                  Authorize Asset
                </button>
              )}

              {isLeadOrAdmin && detailModal.asset.authorization_status === 'AUTHORIZED' && (
                <button
                  type="button"
                  onClick={() => {
                    const target = detailModal.asset;
                    setDetailModal({ open: false, asset: null });
                    setConfirmModal({ open: true, type: 'DISABLE', asset: target });
                  }}
                  style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', color: '#64748B', fontWeight: '600', cursor: 'pointer' }}
                >
                  Disable Asset
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
