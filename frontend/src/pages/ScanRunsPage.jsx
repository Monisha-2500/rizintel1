import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Play, Plus, Server, CheckCircle2, Clock, 
  AlertCircle, Activity, Lock, ShieldCheck, Upload, ExternalLink, RefreshCw,
  X, Search, Filter, AlertTriangle, Check, RotateCcw
} from 'lucide-react';
import { getCurrentUser } from '../services/findingsService';
import { 
  getMyOrganizations, 
  getRegisteredAssets, 
  getScanRuns, 
  getScanRun,
  createScanRun 
} from '../services/workspaceService';
import {
  uploadScannerReport,
  getScanRunSubmissions,
  getScanRunEvents,
  triggerScanRunProcessing,
  getScanRunResults
} from '../services/ingestionService';
import { subscribeToScanRunStream } from '../services/streamService';
import { listScannerAgents } from '../services/agentService';
import { isScannerAvailableFromAgents } from '../utils/capabilityNormalizer';

// Customer-facing pipeline stage journey
const PIPELINE_STAGES = [
  { id: 'SCANNER_REPORTS', label: 'Scanner Reports' },
  { id: 'NORMALIZATION', label: 'Normalization' },
  { id: 'DEDUPLICATION', label: 'Intelligent Deduplication' },
  { id: 'CONFIDENCE_ANALYSIS', label: 'Confidence Analysis' },
  { id: 'THREAT_INTEL', label: 'Threat Intelligence' },
  { id: 'RISK_SCORING', label: 'Risk Scoring' },
  { id: 'EXPLAINABILITY', label: 'Explainability' },
  { id: 'SLA_REMEDIATION', label: 'SLA & Remediation' },
  { id: 'COMPLETED', label: 'Completed' }
];

// Event translation mapping for SOC readability
const EVENT_LABEL_MAP = {
  'SCANNER_JOB_QUEUED': 'Scanner job queued',
  'SCANNER_STARTED': 'Scanner execution started',
  'SCANNER_REPORT_RECEIVED': 'Scanner report received',
  'NORMALIZATION_COMPLETED': 'Normalization completed',
  'DEDUPLICATION_COMPLETED': 'Intelligent deduplication completed',
  'CONFIDENCE_ANALYSIS_COMPLETED': 'Confidence analysis completed',
  'THREAT_INTEL_ENRICHED': 'Threat intelligence enriched',
  'RISK_SCORING_COMPLETED': 'Risk scoring completed',
  'EXPLAINABILITY_GENERATED': 'Explainability insights generated',
  'SLA_ASSIGNED': 'SLA & remediation assigned',
  'SCAN_COMPLETED': 'Scan completed',
  'SCAN_FAILED': 'Scan failed',
};

export default function ScanRunsPage() {
  const navigate = useNavigate();
  const currentUser = getCurrentUser();
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [scanRuns, setScanRuns] = useState([]);
  const [authorizedAssets, setAuthorizedAssets] = useState([]);
  const [activeAgents, setActiveAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [scannerFilter, setScannerFilter] = useState('ALL');

  // Refresh states with visual spinner feedback
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isModalRefreshing, setIsModalRefreshing] = useState(false);

  // Detail modal state
  const [selectedRun, setSelectedRun] = useState(null);
  const [runSubmissions, setRunSubmissions] = useState([]);
  const [runEvents, setRunEvents] = useState([]);
  const [runResults, setRunResults] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Real-time SSE state
  const [connectionStatus, setConnectionStatus] = useState('DISCONNECTED');
  const [liveSnapshot, setLiveSnapshot] = useState(null);

  // Upload modal state
  const [uploadScanner, setUploadScanner] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);

  // Create run modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [formError, setFormError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [scanName, setScanName] = useState('');
  const [scanDescription, setScanDescription] = useState('');
  const [scanners, setScanners] = useState({
    NUCLEI: true,
    ZAP: true,
    WAPITI: true,
  });

  const handleOpenCreateModal = async () => {
    setShowCreateModal(true);
    if (selectedOrg) {
      listScannerAgents(selectedOrg.organization_id)
        .then(agents => setActiveAgents(agents))
        .catch(() => {});
    }
  };

  // Toast feedback state
  const [toast, setToast] = useState(null);

  // Role permissions
  const canCreateRun = currentUser?.role !== 'VIEWER';
  const canUpload = currentUser?.role !== 'VIEWER';
  const canProcess = currentUser?.role === 'SECURITY_LEAD' || currentUser?.role === 'ADMIN';

  useEffect(() => {
    loadData();
  }, []);

  // Modal Escape key listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (uploadScanner) setUploadScanner(null);
        else if (showCreateModal) setShowCreateModal(false);
        else if (selectedRun) setSelectedRun(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [uploadScanner, showCreateModal, selectedRun]);

  // Real-time SSE stream subscription
  useEffect(() => {
    if (!selectedOrg || !selectedRun) {
      setConnectionStatus('DISCONNECTED');
      setLiveSnapshot(null);
      return;
    }

    const orgId = selectedOrg.organization_id;
    const runId = selectedRun.scan_run_id;

    const unsubscribe = subscribeToScanRunStream(orgId, runId, {
      onConnectionChange: (status) => setConnectionStatus(status),
      onSnapshot: (snap) => {
        setLiveSnapshot(snap);
        if (snap.status) {
          setSelectedRun(prev => prev ? { ...prev, status: snap.status } : null);
        }
      },
      onScannerStatus: (data) => {
        if (data.snapshot) setLiveSnapshot(data.snapshot);
        handleRefreshDetail();
      },
      onPipelineStage: (data) => {
        if (data.snapshot) setLiveSnapshot(data.snapshot);
        if (data.metadata?.stage_event) {
          setRunEvents(prev => {
            const exists = prev.some(e => e.event_id === data.metadata.stage_event.event_id);
            return exists ? prev : [...prev, data.metadata.stage_event];
          });
        }
        handleRefreshDetail();
      },
      onCounts: (data) => {
        if (data.snapshot) setLiveSnapshot(data.snapshot);
      },
      onCompleted: (data) => {
        if (data.snapshot) setLiveSnapshot(data.snapshot);
        setSelectedRun(prev => prev ? { ...prev, status: 'COMPLETED' } : null);
        handleRefreshDetail();
        fetchOrgRunsAndAssets(orgId);
      },
      onFailed: (data) => {
        if (data.snapshot) setLiveSnapshot(data.snapshot);
        setSelectedRun(prev => prev ? { ...prev, status: 'FAILED' } : null);
        handleRefreshDetail();
        fetchOrgRunsAndAssets(orgId);
      }
    });

    return () => {
      unsubscribe();
    };
  }, [selectedOrg?.organization_id, selectedRun?.scan_run_id]);

  // Live dynamic polling interval: syncs scan runs, pipeline stages, and events while scans run or modal is open
  useEffect(() => {
    if (!selectedOrg) return;

    const hasActiveRuns = scanRuns.some(r => r.status === 'RUNNING' || r.status === 'PROCESSING' || r.status === 'QUEUED' || r.status === 'WAITING_FOR_INPUT');
    const isModalOpen = Boolean(selectedRun);

    if (!hasActiveRuns && !isModalOpen) return;

    const interval = setInterval(async () => {
      try {
        const orgId = selectedOrg.organization_id;
        const runs = await getScanRuns(orgId).catch(() => []);
        setScanRuns(runs);

        if (selectedRun) {
          const freshRun = runs.find(r => r.scan_run_id === selectedRun.scan_run_id) || selectedRun;
          const [subs, evts] = await Promise.all([
            getScanRunSubmissions(orgId, freshRun.scan_run_id).catch(() => []),
            getScanRunEvents(orgId, freshRun.scan_run_id).catch(() => []),
          ]);
          setSelectedRun(freshRun);
          setRunSubmissions(subs);
          setRunEvents(evts);

          if (freshRun.status === 'COMPLETED') {
            const res = await getScanRunResults(orgId, freshRun.scan_run_id).catch(() => null);
            setRunResults(res);
          }
        }
      } catch (err) {
        console.warn('Background scan run sync error:', err);
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [selectedOrg?.organization_id, selectedRun?.scan_run_id, selectedRun?.status, scanRuns]);

  const showToastNotification = (text, type = 'success') => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 4000);
  };

  async function loadData() {
    try {
      setLoading(true);
      setError(null);
      const orgs = await getMyOrganizations();
      setOrganizations(orgs);
      if (orgs.length > 0) {
        const org = orgs[0];
        setSelectedOrg(org);
        await fetchOrgRunsAndAssets(org.organization_id);
      }
    } catch (err) {
      console.error('Failed to load scan runs:', err);
      setError(err.message || 'Error loading scan runs');
    } finally {
      setLoading(false);
    }
  }

  async function fetchOrgRunsAndAssets(orgId) {
    const [runs, assetList, agents] = await Promise.all([
      getScanRuns(orgId).catch(() => []),
      getRegisteredAssets(orgId).catch(() => []),
      listScannerAgents(orgId).catch(() => [])
    ]);
    setScanRuns(runs);
    setActiveAgents(agents);
    const authOnly = assetList.filter(a => a.authorization_status === 'AUTHORIZED');
    setAuthorizedAssets(authOnly);
    if (authOnly.length > 0) {
      setSelectedAssetId(authOnly[0].asset_id);
    }
  }

  const handleRefreshAll = async () => {
    if (!selectedOrg) return;
    try {
      setIsRefreshing(true);
      await fetchOrgRunsAndAssets(selectedOrg.organization_id);
      showToastNotification('Scan runs refreshed.');
    } catch (err) {
      console.error('Error refreshing scan runs:', err);
    } finally {
      setTimeout(() => setIsRefreshing(false), 400);
    }
  };

  const handleOrgChange = async (orgId) => {
    const org = organizations.find(o => o.organization_id === orgId);
    if (!org) return;
    setSelectedOrg(org);
    try {
      setLoading(true);
      await fetchOrgRunsAndAssets(orgId);
      setSelectedRun(null);
    } catch (err) {
      console.error('Error fetching org data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenDetail = async (run) => {
    setSelectedRun(run);
    if (!selectedOrg) return;
    try {
      setDetailLoading(true);
      const [updatedRun, subs, evts] = await Promise.all([
        getScanRun(selectedOrg.organization_id, run.scan_run_id).catch(() => run),
        getScanRunSubmissions(selectedOrg.organization_id, run.scan_run_id).catch(() => []),
        getScanRunEvents(selectedOrg.organization_id, run.scan_run_id).catch(() => []),
      ]);
      const currentRun = updatedRun || run;
      setSelectedRun(currentRun);
      const res = currentRun.status === 'COMPLETED' 
        ? await getScanRunResults(selectedOrg.organization_id, currentRun.scan_run_id).catch(() => null)
        : null;
      setRunSubmissions(subs);
      setRunEvents(evts);
      setRunResults(res);
    } catch (err) {
      console.error('Error loading scan run details:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleRefreshDetail = async () => {
    if (!selectedRun || !selectedOrg) return;
    try {
      setIsModalRefreshing(true);
      await handleOpenDetail(selectedRun);
      await fetchOrgRunsAndAssets(selectedOrg.organization_id);
    } finally {
      setTimeout(() => setIsModalRefreshing(false), 300);
    }
  };

  const handleFileUploadSubmit = async (e) => {
    e.preventDefault();
    if (!selectedOrg || !selectedRun || !uploadScanner || !selectedFile) return;

    try {
      setUploading(true);
      setUploadError(null);

      await uploadScannerReport(
        selectedOrg.organization_id,
        selectedRun.scan_run_id,
        uploadScanner,
        selectedFile
      );

      showToastNotification(`Report uploaded successfully for ${uploadScanner}.`);
      setUploadScanner(null);
      setSelectedFile(null);
      await fetchOrgRunsAndAssets(selectedOrg.organization_id);
      await handleOpenDetail(selectedRun);
    } catch (err) {
      setUploadError(err.message || 'Failed to upload scanner report');
    } finally {
      setUploading(false);
    }
  };

  const handleTriggerProcess = async () => {
    if (!selectedOrg || !selectedRun) return;
    try {
      setDetailLoading(true);
      await triggerScanRunProcessing(selectedOrg.organization_id, selectedRun.scan_run_id);
      showToastNotification('Security pipeline execution triggered.');
      await new Promise(r => setTimeout(r, 1000));
      await fetchOrgRunsAndAssets(selectedOrg.organization_id);
      await handleOpenDetail(selectedRun);
    } catch (err) {
      showToastNotification(`Pipeline trigger failed: ${err.message}`, 'error');
    } finally {
      setDetailLoading(false);
    }
  };

  // Determine scanner availability based on registered active agents
  const isScannerAvailable = (scannerKey) => {
    return isScannerAvailableFromAgents(activeAgents, scannerKey);
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    if (!selectedOrg || !selectedAssetId) return;

    const selectedScannersList = Object.keys(scanners).filter(k => scanners[k] && isScannerAvailable(k));
    if (selectedScannersList.length === 0) {
      setFormError('At least one available scanner must be selected.');
      return;
    }

    try {
      setIsSubmitting(true);
      setFormError(null);

      const payload = {
        asset_id: selectedAssetId,
        scanner_selections: selectedScannersList,
        data_origin: 'LIVE_SCAN',
      };
      if (scanName.trim()) payload.scan_name = scanName.trim();
      if (scanDescription.trim()) payload.description = scanDescription.trim();

      await createScanRun(selectedOrg.organization_id, payload);

      showToastNotification('Scan run created.');
      setShowCreateModal(false);
      setScanName('');
      setScanDescription('');
      await fetchOrgRunsAndAssets(selectedOrg.organization_id);
    } catch (err) {
      setFormError(err.message || 'Failed to create scan run');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Filter logic
  const filteredScanRuns = scanRuns.filter(run => {
    const scannerList = typeof run.scanner_selections === 'string' ? JSON.parse(run.scanner_selections || '[]') : (run.scanner_selections || []);
    const matchQuery = !searchQuery.trim() || 
      run.scan_run_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      run.asset_id.toLowerCase().includes(searchQuery.toLowerCase());

    const matchStatus = statusFilter === 'ALL' || run.status === statusFilter;
    const matchScanner = scannerFilter === 'ALL' || scannerList.some(s => s.toUpperCase() === scannerFilter.toUpperCase());

    return matchQuery && matchStatus && matchScanner;
  });

  // Calculate dynamic stage status across the 9 pipeline stages
  const getStageStatus = (idx, stageId) => {
    if (!selectedRun) return 'PENDING';
    if (selectedRun.status === 'COMPLETED') return 'COMPLETE';
    if (selectedRun.status === 'FAILED') return 'FAILED';

    let maxCompletedStage = -1;
    if (runEvents && runEvents.length > 0) {
      for (const evt of runEvents) {
        const et = (evt.event_type || '').toUpperCase();
        if (et === 'SCAN_COMPLETED') maxCompletedStage = Math.max(maxCompletedStage, 8);
        else if (et.includes('SLA')) maxCompletedStage = Math.max(maxCompletedStage, 7);
        else if (et.includes('EXPLAINABILITY') || et.includes('EXPLANATION')) maxCompletedStage = Math.max(maxCompletedStage, 6);
        else if (et.includes('RISK_SCORING')) maxCompletedStage = Math.max(maxCompletedStage, 5);
        else if (et.includes('THREAT')) maxCompletedStage = Math.max(maxCompletedStage, 4);
        else if (et.includes('CONFIDENCE')) maxCompletedStage = Math.max(maxCompletedStage, 3);
        else if (et.includes('DEDUPLICATION')) maxCompletedStage = Math.max(maxCompletedStage, 2);
        else if (et.includes('NORMALIZATION')) maxCompletedStage = Math.max(maxCompletedStage, 1);
        else if (et.includes('REPORT') || et.includes('SCANNER') || et.includes('INGEST')) maxCompletedStage = Math.max(maxCompletedStage, 0);
      }
    }

    if (liveSnapshot?.stage_index !== undefined && liveSnapshot.stage_index !== null) {
      maxCompletedStage = Math.max(maxCompletedStage, liveSnapshot.stage_index);
    }

    if (idx <= maxCompletedStage) return 'COMPLETE';
    if (idx === maxCompletedStage + 1 && (selectedRun.status === 'PROCESSING' || selectedRun.status === 'RUNNING')) {
      return 'IN_PROGRESS';
    }
    return 'PENDING';
  };

  // Dynamically calculate accurate pipeline counts
  const counts = useMemo(() => {
    if (liveSnapshot?.counts) return liveSnapshot.counts;
    if (runResults?.summary?.pipeline_summary?.summary) {
      const s = runResults.summary.pipeline_summary.summary;
      return {
        raw_signals: s.raw_findings,
        normalized: s.raw_findings,
        canonical: s.unique_findings,
        duplicates_correlated: s.duplicates_correlated,
        confirmed: s.actionable_findings,
        needs_review: s.pending_review_findings,
        suppressed: s.likely_noise_findings,
      };
    }
    if (runResults?.raw_finding_count != null) {
      const rawCount = runResults.raw_finding_count;
      const canonicalCount = runResults.canonical_finding_count || (runResults.findings?.length ?? 0);
      const findingsList = runResults.findings || [];
      const confirmedCount = findingsList.filter(f => f.confidence_classification === 'CONFIRMED').length;
      const needsReviewCount = findingsList.filter(f => f.confidence_classification === 'NEEDS_REVIEW' || f.confidence_classification == null).length;
      const correlatedCount = Math.max(0, rawCount - canonicalCount);
      return {
        raw_signals: rawCount,
        normalized: rawCount,
        canonical: canonicalCount,
        duplicates_correlated: correlatedCount,
        confirmed: confirmedCount,
        needs_review: needsReviewCount,
        suppressed: 0,
      };
    }
    return null;
  }, [liveSnapshot, runResults]);

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
              Scan Runs
            </h1>
            {!canCreateRun && (
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
            Create and monitor authorized multi-scanner security scans.
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

          {canCreateRun && (
            <button
              id="new-scan-run-btn"
              onClick={handleOpenCreateModal}
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
              <span>New Scan Run</span>
            </button>
          )}
        </div>
      </div>

      {/* Controls Bar: Search & Filters */}
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        gap: '14px', 
        marginBottom: '20px', 
        flexWrap: 'wrap' 
      }}>
        <div style={{ flex: '1', minWidth: '240px', position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#94A3B8' }} />
          <input
            type="text"
            placeholder="Search by scan run ID, asset name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '9px 14px 9px 40px',
              borderRadius: '10px',
              border: '1px solid var(--border-color, #E2E8F0)',
              background: 'var(--bg-card, #FFFFFF)',
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
              <option value="QUEUED">Queued</option>
              <option value="RUNNING">Running</option>
              <option value="PROCESSING">Processing</option>
              <option value="COMPLETED">Completed</option>
              <option value="FAILED">Failed</option>
              <option value="CANCELLED">Cancelled</option>
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
            id="scan-runs-refresh-btn"
            onClick={handleRefreshAll}
            disabled={isRefreshing}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '8px',
              border: '1px solid var(--border-color, #CBD5E1)',
              background: 'var(--bg-card, #FFFFFF)',
              fontSize: '13px',
              fontWeight: '600',
              color: 'var(--text-primary, #475569)',
              cursor: isRefreshing ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease',
              opacity: isRefreshing ? 0.7 : 1
            }}
          >
            <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} />
            <span>{isRefreshing ? 'Refreshing…' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* Content Area */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: '#64748B', fontSize: '14px' }}>
          <RefreshCw size={24} className="spin" style={{ marginBottom: '10px', color: '#6366F1' }} />
          <div>Loading scan runs...</div>
        </div>
      ) : error ? (
        <div style={{ background: '#FEF2F2', border: '1px solid #FCA5A5', color: '#991B1B', padding: '20px', borderRadius: '12px', textAlign: 'center' }}>
          <AlertCircle size={28} style={{ marginBottom: '8px', color: '#DC2626' }} />
          <h3 style={{ margin: '0 0 6px 0', fontSize: '16px' }}>Unable to load scan runs</h3>
          <p style={{ margin: '0 0 16px 0', fontSize: '13.5px', color: '#7F1D1D' }}>We couldn't retrieve scan activity right now.</p>
          <button
            onClick={loadData}
            style={{ padding: '8px 18px', borderRadius: '8px', border: 'none', background: '#DC2626', color: '#FFF', fontWeight: '600', cursor: 'pointer', fontSize: '13px' }}
          >
            Retry
          </button>
        </div>
      ) : scanRuns.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 20px', background: 'var(--bg-card, #FFFFFF)', borderRadius: '16px', border: '1px solid var(--border-color, #E2E8F0)', boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
          <div style={{ background: '#EEF2FF', width: '56px', height: '56px', borderRadius: '16px', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px auto' }}>
            <Play size={28} color="#4F46E5" />
          </div>
          <h3 style={{ margin: '0 0 6px 0', color: 'var(--text-primary, #0F172A)', fontSize: '18px', fontWeight: '700' }}>
            No scan runs yet
          </h3>
          <p style={{ color: 'var(--text-secondary, #64748B)', fontSize: '14px', margin: '0 auto 20px auto', maxWidth: '460px', lineHeight: '1.5' }}>
            {canCreateRun 
              ? 'Create an authorized scan run to begin scanner execution and security analysis.' 
              : 'Scan runs will appear here after an authorized user launches security scanning.'}
          </p>
          {canCreateRun && (
            <button
              onClick={() => setShowCreateModal(true)}
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
              <Plus size={16} /> Create First Scan Run
            </button>
          )}
        </div>
      ) : filteredScanRuns.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '50px 20px', background: 'var(--bg-card, #FFFFFF)', borderRadius: '14px', border: '1px solid var(--border-color, #E2E8F0)' }}>
          <Filter size={32} style={{ color: '#94A3B8', marginBottom: '12px' }} />
          <h3 style={{ margin: '0 0 6px 0', color: 'var(--text-primary, #0F172A)', fontSize: '16px', fontWeight: '700' }}>No scan runs match your filters</h3>
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
                <th style={{ padding: '12px 16px' }}>Scan Run ID</th>
                <th style={{ padding: '12px 16px' }}>Asset Target</th>
                <th style={{ padding: '12px 16px' }}>Scanners</th>
                <th style={{ padding: '12px 16px' }}>Consensus</th>
                <th style={{ padding: '12px 16px' }}>Status</th>
                <th style={{ padding: '12px 16px' }}>Created At</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredScanRuns.map(run => {
                const scannerList = typeof run.scanner_selections === 'string' ? JSON.parse(run.scanner_selections || '[]') : (run.scanner_selections || []);
                const received = typeof run.received_scanners === 'string' ? JSON.parse(run.received_scanners || '[]') : (run.received_scanners || []);
                const isCompleted = run.status === 'COMPLETED';
                const isFailed = run.status === 'FAILED';
                const isRunning = run.status === 'RUNNING' || run.status === 'PROCESSING';
                const assetObj = (authorizedAssets || []).find(a => a.asset_id === run.asset_id);
                const assetDisplayName = assetObj ? assetObj.display_name : run.asset_id;

                return (
                  <tr key={run.scan_run_id} style={{ borderBottom: '1px solid var(--border-color, #F1F5F9)' }}>
                    <td style={{ padding: '14px 16px', fontWeight: '700', color: 'var(--text-primary, #0F172A)', fontFamily: 'monospace' }}>
                      {run.scan_run_id}
                    </td>
                    <td style={{ padding: '14px 16px', color: 'var(--text-primary, #334155)' }}>
                      <div style={{ fontWeight: '600', color: 'var(--text-primary, #0F172A)' }}>{assetDisplayName}</div>
                      {assetObj && <div style={{ fontSize: '11px', color: 'var(--text-secondary, #64748B)', fontFamily: 'monospace' }}>{run.asset_id}</div>}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                        {scannerList.map(s => (
                          <span key={s} style={{ background: 'var(--bg-lavender, #EEF2FF)', color: '#818CF8', padding: '2px 8px', borderRadius: '6px', fontSize: '11.5px', fontWeight: '700', border: '1px solid rgba(99, 102, 241, 0.3)' }}>
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{ padding: '14px 16px', fontWeight: '600', color: 'var(--text-secondary, #64748B)' }}>
                      {received.length} / {scannerList.length}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        padding: '4px 10px',
                        borderRadius: '12px',
                        fontSize: '12px',
                        fontWeight: '700',
                        background: isCompleted ? '#DCFCE7' : isFailed ? '#FEE2E2' : isRunning ? '#DBEAFE' : '#FEF3C7',
                        color: isCompleted ? '#15803D' : isFailed ? '#991B1B' : isRunning ? '#1E40AF' : '#D97706'
                      }}>
                        {run.status}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px', color: 'var(--text-secondary, #64748B)', fontSize: '12.5px' }}>
                      {new Date(run.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                      <button
                        onClick={() => handleOpenDetail(run)}
                        style={{
                          padding: '6px 14px',
                          borderRadius: '8px',
                          border: '1px solid var(--border-color, #CBD5E1)',
                          background: 'var(--bg-surface-elevated, #FFFFFF)',
                          fontWeight: '600',
                          cursor: 'pointer',
                          fontSize: '13px',
                          color: 'var(--text-primary, #334155)'
                        }}
                      >
                        Manage Run
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Detail Modal with SSE Live Pipeline Journey */}
      {selectedRun && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setSelectedRun(null); }}
          style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2000,
            padding: '16px'
          }}
        >
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            borderRadius: '16px',
            padding: '24px 28px',
            width: '95%',
            maxWidth: '1200px',
            maxHeight: '92vh',
            overflowY: 'auto',
            boxShadow: '0 25px 50px -12px rgba(0,0,0,0.25)',
            position: 'relative'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid #E2E8F0' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <h2 style={{ fontSize: '20px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                    Scan Run Details: {selectedRun.scan_run_id}
                  </h2>
                  <span style={{
                    padding: '4px 10px',
                    borderRadius: '12px',
                    fontSize: '11.5px',
                    fontWeight: '700',
                    background: selectedRun.status === 'COMPLETED' ? '#DCFCE7' : selectedRun.status === 'FAILED' ? '#FEE2E2' : '#FEF3C7',
                    color: selectedRun.status === 'COMPLETED' ? '#15803D' : selectedRun.status === 'FAILED' ? '#991B1B' : '#D97706'
                  }}>
                    {selectedRun.status}
                  </span>

                  <span style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    padding: '3px 10px',
                    borderRadius: '12px',
                    fontSize: '11px',
                    fontWeight: '700',
                    background: connectionStatus === 'LIVE' ? '#D1FAE5' : connectionStatus === 'RECONNECTING' ? '#FEF3C7' : '#F1F5F9',
                    color: connectionStatus === 'LIVE' ? '#047857' : connectionStatus === 'RECONNECTING' ? '#B45309' : '#64748B'
                  }}>
                    <span style={{
                      width: '7px', height: '7px', borderRadius: '50%',
                      background: connectionStatus === 'LIVE' ? '#10B981' : connectionStatus === 'RECONNECTING' ? '#F59E0B' : '#94A3B8'
                    }} />
                    {connectionStatus === 'LIVE' ? 'Live Updates' : connectionStatus === 'RECONNECTING' ? 'Reconnecting…' : 'Disconnected'}
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: '#64748B', marginTop: '4px' }}>
                  Target Asset: <strong>{selectedRun.asset_id}</strong> | Org: {selectedOrg?.organization_id}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <button
                  id="scan-run-detail-refresh-btn"
                  onClick={handleRefreshDetail}
                  disabled={isModalRefreshing || detailLoading}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '8px',
                    border: '1px solid #CBD5E1',
                    background: '#FFF',
                    cursor: (isModalRefreshing || detailLoading) ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '13px',
                    fontWeight: '600',
                    color: '#475569',
                    transition: 'all 0.15s ease',
                    opacity: (isModalRefreshing || detailLoading) ? 0.7 : 1
                  }}
                >
                  <RefreshCw size={14} className={(isModalRefreshing || detailLoading) ? 'spin' : ''} />
                  <span>{(isModalRefreshing || detailLoading) ? 'Refreshing…' : 'Refresh'}</span>
                </button>
                <button
                  onClick={() => setSelectedRun(null)}
                  aria-label="Close"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px', color: '#64748B', borderRadius: '6px' }}
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Customer Stage Progress Journey */}
            <div style={{ marginBottom: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                  Security Processing Stage Journey
                </h3>
                <span style={{ fontSize: '12px', color: '#64748B', fontWeight: '500' }}>
                  {selectedRun.status === 'COMPLETED' ? 'All 9 Stages Verified' : selectedRun.status === 'PROCESSING' ? 'Pipeline Active' : 'Autonomous Workflow'}
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(105px, 1fr))', gap: '6px' }}>
                {PIPELINE_STAGES.map((stg, idx) => {
                  const status = getStageStatus(idx, stg.id);
                  const isDone = status === 'COMPLETE';
                  const isCurrent = status === 'IN_PROGRESS';
                  const isFailed = status === 'FAILED';

                  return (
                    <div 
                      key={stg.id} 
                      id={`stage-${stg.id.toLowerCase()}`}
                      style={{
                        padding: '10px 6px',
                        borderRadius: '8px',
                        background: isDone ? '#ECFDF5' : isCurrent ? '#EEF2FF' : isFailed ? '#FEF2F2' : '#F1F5F9',
                        border: `1.5px solid ${isDone ? '#6EE7B7' : isCurrent ? '#818CF8' : isFailed ? '#FCA5A5' : '#CBD5E1'}`,
                        boxShadow: isCurrent ? '0 0 0 3px rgba(99, 102, 241, 0.2)' : 'none',
                        textAlign: 'center',
                        transition: 'all 0.25s ease'
                      }}
                    >
                      <div style={{ fontSize: '11px', fontWeight: '700', color: isDone ? '#065F46' : isCurrent ? '#312E81' : isFailed ? '#991B1B' : '#1E293B', marginBottom: '3px', lineHeight: '1.2' }}>
                        {idx + 1}. {stg.label}
                      </div>
                      <div style={{ 
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '3px',
                        fontSize: '10px', 
                        color: isDone ? '#059669' : isCurrent ? '#4F46E5' : isFailed ? '#DC2626' : '#475569', 
                        fontWeight: '700' 
                      }}>
                        {isDone ? (
                          <>
                            <CheckCircle2 size={10} color="#059669" /> Complete
                          </>
                        ) : isCurrent ? (
                          <>
                            <Activity size={10} className="spin" color="#4F46E5" /> In Progress
                          </>
                        ) : isFailed ? (
                          <>
                            <AlertCircle size={10} color="#DC2626" /> Failed
                          </>
                        ) : (
                          <>
                            <Clock size={10} color="#64748B" /> Pending
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Scanner Ingestion Cards */}
            <h3 style={{ fontSize: '14px', fontWeight: '700', marginBottom: '12px', color: '#0F172A' }}>
              Multi-Scanner Ingestion Status
            </h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '14px', marginBottom: '24px' }}>
              {(typeof selectedRun.scanner_selections === 'string' ? JSON.parse(selectedRun.scanner_selections || '[]') : (selectedRun.scanner_selections || [])).map(scanner => {
                const liveCard = liveSnapshot?.scanners?.find(s => s.scanner.toUpperCase() === scanner.toUpperCase());
                const sub = runSubmissions.find(s => s.scanner.toUpperCase() === scanner.toUpperCase());
                
                let status = liveCard?.status || (sub ? 'RECEIVED' : 'PENDING');
                if (sub?.processing_status === 'TARGET_REVIEW_REQUIRED') status = 'TARGET_REVIEW_REQUIRED';
                if (sub?.processing_status === 'FAILED') status = 'FAILED';

                const isReceived = status === 'RECEIVED';
                const isReview = status === 'TARGET_REVIEW_REQUIRED';
                const isFailed = status === 'FAILED';

                return (
                  <div key={scanner} style={{
                    background: isReceived ? '#F0FDF4' : isReview ? '#FFFBEB' : isFailed ? '#FEF2F2' : '#F8FAFC',
                    border: `1px solid ${isReceived ? '#86EFAC' : isReview ? '#FDE68A' : isFailed ? '#FCA5A5' : '#E2E8F0'}`,
                    borderRadius: '10px',
                    padding: '16px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <span style={{ fontSize: '15px', fontWeight: '700', color: '#0F172A' }}>{scanner}</span>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: '700',
                        padding: '2px 8px',
                        borderRadius: '10px',
                        background: isReceived ? '#DCFCE7' : isReview ? '#FEF3C7' : isFailed ? '#FEE2E2' : '#F1F5F9',
                        color: isReceived ? '#15803D' : isReview ? '#D97706' : isFailed ? '#991B1B' : '#64748B'
                      }}>
                        {status}
                      </span>
                    </div>

                    <div style={{ fontSize: '12px', color: '#64748B', marginBottom: '12px' }}>
                      {sub ? (
                        <>
                          <div>Raw Signals: <strong>{sub.raw_finding_count || liveCard?.raw_finding_count || 0}</strong></div>
                          <div>Received: {new Date(sub.received_at || Date.now()).toLocaleTimeString()}</div>
                        </>
                      ) : (
                        <div>Awaiting scanner report submission</div>
                      )}
                    </div>

                    {isReview && (
                      <div style={{ background: '#FEF3C7', border: '1px solid #FDE68A', padding: '8px', borderRadius: '6px', fontSize: '11.5px', color: '#92400E', marginBottom: '10px' }}>
                        The scanner could not safely continue until the target configuration is reviewed.
                      </div>
                    )}

                    {canUpload && selectedRun.status !== 'COMPLETED' && selectedRun.status !== 'PROCESSING' && (
                      <button
                        onClick={() => setUploadScanner(scanner)}
                        style={{
                          width: '100%',
                          padding: '6px 12px',
                          borderRadius: '6px',
                          border: 'none',
                          background: isReceived ? '#F1F5F9' : '#3B82F6',
                          color: isReceived ? '#475569' : '#FFF',
                          fontSize: '12px',
                          fontWeight: '600',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: '6px'
                        }}
                      >
                        <Upload size={14} /> {isReceived ? 'Re-upload Report' : 'Upload Report'}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Real Pipeline Counts */}
            <div style={{ marginBottom: '24px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: '700', marginBottom: '10px', color: 'var(--text-primary, #0F172A)' }}>
                Live Pipeline Counts
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: '10px' }}>
                <div style={{ background: 'var(--bg-surface-elevated, #F8FAFC)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748B)', fontWeight: '700' }}>RAW SIGNALS</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--text-primary, #0F172A)' }}>{counts ? counts.raw_signals : '—'}</div>
                </div>
                <div style={{ background: 'var(--bg-surface-elevated, #F8FAFC)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748B)', fontWeight: '700' }}>NORMALIZED</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--text-primary, #0F172A)' }}>{counts ? counts.normalized : '—'}</div>
                </div>
                <div style={{ background: 'var(--bg-surface-elevated, #F8FAFC)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748B)', fontWeight: '700' }}>CANONICAL</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: '#818CF8' }}>{counts ? counts.canonical : '—'}</div>
                </div>
                <div style={{ background: 'var(--bg-surface-elevated, #F8FAFC)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748B)', fontWeight: '700' }}>CORRELATED</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--text-primary, #0F172A)' }}>{counts ? counts.duplicates_correlated : '—'}</div>
                </div>
                <div style={{ background: 'rgba(16, 185, 129, 0.12)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.3)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: '#10B981', fontWeight: '700' }}>CONFIRMED</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: '#10B981' }}>{counts ? counts.confirmed : '—'}</div>
                </div>
                <div style={{ background: 'rgba(245, 158, 11, 0.12)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(245, 158, 11, 0.3)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: '#F59E0B', fontWeight: '700' }}>NEEDS REVIEW</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: '#F59E0B' }}>{counts ? counts.needs_review : '—'}</div>
                </div>
                <div style={{ background: 'var(--bg-surface-elevated, #F8FAFC)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted, #64748B)', fontWeight: '700' }}>SUPPRESSED</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--text-muted, #64748B)' }}>{counts ? counts.suppressed : '—'}</div>
                </div>
              </div>
            </div>

            {/* Action Bar */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-surface-elevated, #F8FAFC)', padding: '16px', borderRadius: '10px', marginBottom: '24px', border: '1px solid var(--border-color, #E2E8F0)', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '13.5px', fontWeight: '700', color: 'var(--text-primary, #0F172A)' }}>
                  {selectedRun.status === 'COMPLETED' ? 'Scan Completed' : selectedRun.status === 'FAILED' ? 'Scan Failed' : 'Security Processing Pipeline'}
                </span>
                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary, #64748B)', margin: '2px 0 0 0' }}>
                  {selectedRun.status === 'COMPLETED' 
                    ? 'Security pipeline processing complete. Results are available in Command Center.'
                    : selectedRun.status === 'PROCESSING'
                    ? 'Security processing pipeline executing...'
                    : 'Automatic execution triggers when selected scanner reports are received.'}
                </p>
              </div>

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                {canProcess && selectedRun.status !== 'COMPLETED' && selectedRun.status !== 'PROCESSING' && runSubmissions.length > 0 && (
                  <button
                    onClick={handleTriggerProcess}
                    style={{
                      padding: '8px 16px',
                      borderRadius: '8px',
                      border: 'none',
                      background: '#6366F1',
                      color: '#FFF',
                      fontSize: '13px',
                      fontWeight: '600',
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                  >
                    <Play size={14} /> Process Available Results ({runSubmissions.length} Received)
                  </button>
                )}

                <button
                  id="open-command-center-btn"
                  onClick={() => {
                    if (selectedRun.status === 'COMPLETED') {
                      navigate(`/command-center?scan_run_id=${selectedRun.scan_run_id}&org_id=${selectedOrg.organization_id}`);
                    }
                  }}
                  disabled={selectedRun.status !== 'COMPLETED'}
                  style={{
                    padding: '8px 16px',
                    borderRadius: '8px',
                    border: 'none',
                    background: selectedRun.status === 'COMPLETED' ? '#10B981' : '#E2E8F0',
                    color: selectedRun.status === 'COMPLETED' ? '#FFF' : '#94A3B8',
                    fontSize: '13px',
                    fontWeight: '600',
                    cursor: selectedRun.status === 'COMPLETED' ? 'pointer' : 'not-allowed',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <ExternalLink size={14} /> {selectedRun.status === 'COMPLETED' ? 'Open Command Center Results' : 'Open Command Center'}
                </button>
              </div>
            </div>

            {/* Event Timeline */}
            <h3 style={{ fontSize: '14px', fontWeight: '700', marginBottom: '12px', color: '#0F172A' }}>
              Pipeline Event Timeline
            </h3>

            <div style={{ background: '#0F172A', borderRadius: '10px', padding: '16px', color: '#F8FAFC', fontSize: '12px', fontFamily: 'monospace', maxHeight: '220px', overflowY: 'auto' }}>
              {runEvents.length === 0 ? (
                <div style={{ color: '#64748B' }}>No pipeline events recorded for this scan run yet.</div>
              ) : (
                runEvents.map((evt, idx) => {
                  const eventTitle = EVENT_LABEL_MAP[evt.event_type] || evt.event_type;
                  return (
                    <div key={evt.event_id || idx} style={{ marginBottom: '8px', display: 'flex', gap: '12px', alignItems: 'baseline' }}>
                      <span style={{ color: '#64748B' }}>{new Date(evt.created_at || Date.now()).toLocaleTimeString()}</span>
                      <span style={{ color: evt.status === 'SUCCESS' ? '#4ADE80' : evt.status === 'FAILED' ? '#F87171' : '#38BDF8', fontWeight: '600' }}>
                        [{evt.event_type}]
                      </span>
                      <span style={{ color: '#94A3B8', fontSize: '11.5px' }}>
                        ({eventTitle})
                      </span>
                      <span style={{ color: '#CBD5E1' }}>{evt.message}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* Upload File Modal */}
      {uploadScanner && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setUploadScanner(null); }}
          style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2100, padding: '16px'
          }}
        >
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            borderRadius: '14px',
            padding: '24px 28px',
            width: '100%',
            maxWidth: '480px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            position: 'relative'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '17px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                Upload {uploadScanner} Report
              </h3>
              <button
                onClick={() => setUploadScanner(null)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748B', padding: 0 }}
              >
                <X size={18} />
              </button>
            </div>

            {uploadError && (
              <div style={{ background: '#FEF2F2', border: '1px solid #FCA5A5', color: '#991B1B', padding: '10px', borderRadius: '6px', fontSize: '13px', marginBottom: '16px' }}>
                {uploadError}
              </div>
            )}

            <form onSubmit={handleFileUploadSubmit}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                  Select {uploadScanner} Export File (.json / .jsonl)
                </label>
                <input 
                  type="file"
                  required
                  accept=".json,.jsonl,.txt"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #CBD5E1', fontSize: '13px' }}
                />
              </div>

              <div style={{ background: '#F8FAFC', padding: '10px', borderRadius: '6px', fontSize: '12px', color: '#64748B', marginBottom: '20px' }}>
                Report target host will be validated against authorized asset. SHA-256 idempotency prevents duplicate counting.
              </div>

              <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => setUploadScanner(null)}
                  style={{ padding: '8px 16px', borderRadius: '6px', border: '1px solid #CBD5E1', background: '#FFF', cursor: 'pointer', fontSize: '13px', color: '#475569' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading || !selectedFile}
                  style={{ padding: '8px 16px', borderRadius: '6px', border: 'none', background: '#3B82F6', color: '#FFF', fontWeight: '600', cursor: 'pointer', fontSize: '13px' }}
                >
                  {uploading ? 'Ingesting...' : 'Ingest Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Scan Run Modal (Or No Authorized Assets State) */}
      {showCreateModal && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) setShowCreateModal(false); }}
          style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 2000, padding: '16px'
          }}
        >
          <div style={{
            background: 'var(--bg-card, #FFFFFF)',
            borderRadius: '14px',
            padding: '24px 28px',
            width: '100%',
            maxWidth: '520px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            position: 'relative'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
              <h2 style={{ fontSize: '18px', fontWeight: '700', margin: 0, color: '#0F172A' }}>
                {authorizedAssets.length === 0 ? 'No Authorized Assets' : 'Create Scan Run'}
              </h2>
              <button
                onClick={() => setShowCreateModal(false)}
                aria-label="Close"
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: '#64748B', borderRadius: '6px' }}
              >
                <X size={20} />
              </button>
            </div>

            {formError && (
              <div style={{ background: '#FEF2F2', border: '1px solid #FCA5A5', color: '#991B1B', padding: '10px 14px', borderRadius: '8px', fontSize: '13px', marginBottom: '16px' }}>
                {formError}
              </div>
            )}

            {/* No Authorized Assets State */}
            {authorizedAssets.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 12px' }}>
                <div style={{ background: '#EEF2FF', width: '48px', height: '48px', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 14px auto' }}>
                  <ShieldCheck size={24} color="#6366F1" />
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#0F172A', margin: '0 0 6px 0' }}>
                  No authorized assets available
                </h3>
                <p style={{ fontSize: '13.5px', color: '#64748B', margin: '0 0 18px 0', lineHeight: '1.45' }}>
                  Assets must be authorized before security scans can be created.
                </p>

                {canCreateRun ? (
                  <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                    <button
                      type="button"
                      onClick={() => setShowCreateModal(false)}
                      style={{ padding: '9px 18px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', fontWeight: '600', fontSize: '13px', cursor: 'pointer', color: '#475569' }}
                    >
                      Close
                    </button>
                    <button
                      type="button"
                      onClick={() => { setShowCreateModal(false); navigate('/asset-registry'); }}
                      style={{ padding: '9px 18px', borderRadius: '8px', border: 'none', background: '#4F46E5', color: '#FFF', fontWeight: '600', fontSize: '13px', cursor: 'pointer' }}
                    >
                      Go to Asset Registry
                    </button>
                  </div>
                ) : (
                  <div>
                    <p style={{ fontSize: '12.5px', color: '#D97706', background: '#FEF3C7', padding: '8px 12px', borderRadius: '8px', margin: '0 0 16px 0' }}>
                      Asset authorization requires Security Lead or Administrator access.
                    </p>
                    <button
                      type="button"
                      onClick={() => setShowCreateModal(false)}
                      style={{ padding: '8px 18px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', fontWeight: '600', fontSize: '13px', cursor: 'pointer', color: '#475569' }}
                    >
                      Close
                    </button>
                  </div>
                )}
              </div>
            ) : (
              /* Create Scan Run Form */
              <form onSubmit={handleCreateSubmit}>
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px', color: '#334155' }}>
                    Target Asset (Authorized Only) *
                  </label>
                  <select
                    value={selectedAssetId}
                    onChange={(e) => setSelectedAssetId(e.target.value)}
                    style={{ width: '100%', padding: '9px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '13.5px', background: '#FFF', color: '#0F172A', outline: 'none' }}
                  >
                    {authorizedAssets.map(a => (
                      <option key={a.asset_id} value={a.asset_id}>
                        {a.display_name} ({a.normalized_host || a.host}:{a.port})
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '8px', color: '#334155' }}>
                    Select Scanners *
                  </label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {[
                      { key: 'NUCLEI', label: 'Nuclei', desc: 'Vulnerability & misconfiguration scanner' },
                      { key: 'ZAP', label: 'OWASP ZAP', desc: 'Web application security scanner' },
                      { key: 'WAPITI', label: 'Wapiti', desc: 'Web application vulnerability scanner' }
                    ].map(scanner => {
                      const available = isScannerAvailable(scanner.key);
                      return (
                        <label 
                          key={scanner.key} 
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '10px 14px',
                            borderRadius: '8px',
                            border: `1px solid ${scanners[scanner.key] ? '#818CF8' : '#E2E8F0'}`,
                            background: scanners[scanner.key] ? '#EEF2FF' : '#F8FAFC',
                            cursor: available ? 'pointer' : 'not-allowed',
                            opacity: available ? 1 : 0.65
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <input 
                              type="checkbox"
                              disabled={!available}
                              checked={scanners[scanner.key] && available}
                              onChange={() => setScanners(prev => ({ ...prev, [scanner.key]: !prev[scanner.key] }))}
                            />
                            <div>
                              <span style={{ fontSize: '13.5px', fontWeight: '700', color: '#0F172A' }}>{scanner.label}</span>
                              <span style={{ fontSize: '12px', color: '#64748B', marginLeft: '8px' }}>{scanner.desc}</span>
                            </div>
                          </div>

                          <span style={{
                            fontSize: '11px',
                            fontWeight: '700',
                            padding: '2px 8px',
                            borderRadius: '10px',
                            background: available ? '#DCFCE7' : '#F1F5F9',
                            color: available ? '#15803D' : '#64748B'
                          }}>
                            {available ? 'Available' : 'Unavailable'}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px', color: '#334155' }}>
                    Scan Name (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Payment Gateway Nightly Scan"
                    value={scanName}
                    onChange={(e) => setScanName(e.target.value)}
                    style={{ width: '100%', padding: '8px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '13.5px', boxSizing: 'border-box' }}
                  />
                </div>

                <div style={{ marginBottom: '20px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px', color: '#334155' }}>
                    Description (Optional)
                  </label>
                  <textarea
                    rows={2}
                    placeholder="Describe purpose or scope of this scan run..."
                    value={scanDescription}
                    onChange={(e) => setScanDescription(e.target.value)}
                    style={{ width: '100%', padding: '8px 12px', borderRadius: '8px', border: '1px solid #CBD5E1', fontSize: '13.5px', boxSizing: 'border-box', fontFamily: 'inherit' }}
                  />
                </div>

                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    style={{ padding: '9px 18px', borderRadius: '8px', border: '1px solid #CBD5E1', background: '#FFF', cursor: 'pointer', fontSize: '13.5px', fontWeight: '600', color: '#475569' }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting || !selectedAssetId || !Object.keys(scanners).some(k => scanners[k] && isScannerAvailable(k))}
                    style={{
                      padding: '9px 18px',
                      borderRadius: '8px',
                      border: 'none',
                      background: (isSubmitting || !selectedAssetId || !Object.keys(scanners).some(k => scanners[k] && isScannerAvailable(k))) ? '#94A3B8' : '#4F46E5',
                      color: '#FFF',
                      fontWeight: '600',
                      fontSize: '13.5px',
                      cursor: (isSubmitting || !selectedAssetId || !Object.keys(scanners).some(k => scanners[k] && isScannerAvailable(k))) ? 'not-allowed' : 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                  >
                    <Play size={15} />
                    <span>{isSubmitting ? 'Creating...' : 'Create Scan Run'}</span>
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
