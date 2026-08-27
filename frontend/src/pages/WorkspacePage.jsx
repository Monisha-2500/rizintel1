import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Building2, Server, Play, ShieldAlert, CheckCircle2,
  Clock, ArrowRight, ShieldCheck, Plus, ExternalLink, Activity,
  Radio, GitMerge, Cpu, BarChart3, AlertCircle, Info, Layers, RefreshCw,
  User, Check, AlertTriangle, Shield, Key, Compass, Globe, Calendar
} from 'lucide-react';
import { getCurrentUser } from '../services/findingsService';
import {
  getMyOrganizations,
  getRegisteredAssets,
  getScanRuns
} from '../services/workspaceService';
import { listScannerAgents } from '../services/agentService';

export default function WorkspacePage() {
  const navigate = useNavigate();
  const currentUser = getCurrentUser();

  const [organizations, setOrganizations] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [assets, setAssets] = useState([]);
  const [agents, setAgents] = useState([]);
  const [scanRuns, setScanRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showTechDetails, setShowTechDetails] = useState(false);

  useEffect(() => {
    loadWorkspaceData();
  }, []);

  async function loadWorkspaceData() {
    try {
      setLoading(true);
      setError(null);
      const orgs = await getMyOrganizations();
      setOrganizations(orgs || []);

      if (orgs && orgs.length > 0) {
        const currentOrg = orgs[0];
        setSelectedOrg(currentOrg);

        const orgId = currentOrg.organization_id;
        const [fetchedAssets, fetchedAgents, fetchedRuns] = await Promise.all([
          getRegisteredAssets(orgId).catch(() => []),
          listScannerAgents(orgId).catch(() => []),
          getScanRuns(orgId).catch(() => [])
        ]);

        setAssets(fetchedAssets || []);
        setAgents(fetchedAgents || []);
        setScanRuns(fetchedRuns || []);
      }
    } catch (err) {
      console.error('Failed to load workspace data:', err);
      setError(err.message || 'Workspace status couldn\'t be loaded.');
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
      setError(null);
      const [fetchedAssets, fetchedAgents, fetchedRuns] = await Promise.all([
        getRegisteredAssets(orgId).catch(() => []),
        listScannerAgents(orgId).catch(() => []),
        getScanRuns(orgId).catch(() => [])
      ]);
      setAssets(fetchedAssets || []);
      setAgents(fetchedAgents || []);
      setScanRuns(fetchedRuns || []);
    } catch (err) {
      console.error('Error changing workspace org:', err);
      setError('Could not switch organization workspace');
    } finally {
      setLoading(false);
    }
  };

  const isLeadOrAdmin = ['SECURITY_LEAD', 'ADMIN'].includes(currentUser?.role);

  // Time formatting helper
  function formatTimeAgo(dateInput) {
    if (!dateInput) return 'Recently';
    const date = new Date(dateInput);
    if (isNaN(date.getTime())) return 'Recently';
    const now = new Date();
    const diffSec = Math.floor((now - date) / 1000);
    if (diffSec < 60) return 'Just now';
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin} min ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr} hr ago`;
    const diffDays = Math.floor(diffHr / 24);
    return `${diffDays}d ago`;
  }

  // Summary Metrics Derived from State
  const totalAssets = assets.length;
  const activeAssets = assets.filter(a => a.authorization_status === 'AUTHORIZED' || a.status === 'ACTIVE').length || totalAssets;
  const internalAssets = assets.filter(a => a.environment === 'INTERNAL' || a.environment === 'DEVELOPMENT' || a.data_sensitivity === 'HIGH').length;

  const totalAgents = agents.length;
  const connectedAgents = agents.filter(a => a.status === 'CONNECTED' || a.status === 'ACTIVE' || !a.status).length || (totalAgents > 0 ? totalAgents : 0);
  const offlineAgents = agents.filter(a => a.status === 'OFFLINE' || a.status === 'REVOKED').length;

  const totalScanRuns = scanRuns.length;
  const activeRuns = scanRuns.filter(r => r.status === 'WAITING_FOR_INPUT' || r.status === 'INGESTING' || r.status === 'PROCESSING');
  const completedRuns = scanRuns.filter(r => r.status === 'COMPLETED');
  const lastRun = scanRuns.length > 0 ? scanRuns[0] : null;
  const lastRunTimeText = lastRun ? formatTimeAgo(lastRun.created_at) : 'No scan runs yet';

  // Workspace Header Status Derivation
  let statusBadge = {
    label: 'Operational',
    color: '#10B981',
    bg: '#ECFDF5',
    subText: 'Security pipeline available'
  };

  if (totalAssets === 0 || totalAgents === 0) {
    statusBadge = {
      label: 'Setup Required',
      color: '#F59E0B',
      bg: '#FEF3C7',
      subText: 'Connect assets & scanner agents'
    };
  } else if (activeRuns.length > 0) {
    statusBadge = {
      label: 'Processing',
      color: '#2563EB',
      bg: '#EFF6FF',
      subText: 'Security pipeline actively analyzing'
    };
  } else if (error) {
    statusBadge = {
      label: 'Degraded',
      color: '#EF4444',
      bg: '#FEF2F2',
      subText: 'Workspace status couldn\'t be loaded'
    };
  }

  // Operational Readiness 4-Step States
  const step1State = totalAssets > 0 ? 'COMPLETE' : 'NOT_STARTED';
  const step2State = totalAgents > 0 ? 'COMPLETE' : (totalAssets > 0 ? 'NOT_STARTED' : 'NOT_STARTED');
  const step3State = activeRuns.length > 0 ? 'IN_PROGRESS' : (totalScanRuns > 0 ? 'COMPLETE' : 'NOT_STARTED');
  const step4State = completedRuns.length > 0 ? 'COMPLETE' : (activeRuns.length > 0 ? 'IN_PROGRESS' : 'NOT_STARTED');

  // Next Best Action Determination
  let nextAction = {
    title: 'Register your first asset',
    desc: 'Add an authorized application, API or infrastructure target before connecting scanner workflows.',
    btnText: 'Register Asset →',
    route: '/asset-registry',
    icon: Server
  };

  if (totalAssets === 0) {
    nextAction = {
      title: 'Register your first asset',
      desc: 'Add an authorized application, API or infrastructure target before connecting scanner workflows.',
      btnText: 'Register Asset →',
      route: '/asset-registry',
      icon: Server
    };
  } else if (totalAgents === 0) {
    nextAction = {
      title: 'Connect a scanner agent',
      desc: 'Configure an approved scanner agent (ZAP, Nuclei, Wapiti) to collect vulnerability signals.',
      btnText: 'Configure Scanner →',
      route: '/scanner-agents',
      icon: Radio
    };
  } else if (totalScanRuns === 0) {
    nextAction = {
      title: 'Run your first authorized scan',
      desc: 'You have assets and scanners configured. Execute an authorized scan to start the risk analysis pipeline.',
      btnText: 'Start Scan →',
      route: '/scan-runs',
      icon: Play
    };
  } else if (activeRuns.length > 0) {
    nextAction = {
      title: 'Monitor scan processing',
      desc: 'Scan runs are currently ingesting or processing security findings through the analysis pipeline.',
      btnText: 'View Scan Runs →',
      route: '/scan-runs',
      icon: Activity
    };
  } else {
    nextAction = {
      title: 'Review prioritized findings',
      desc: 'Security findings have been normalized, deduplicated, and risk-scored through the analysis pipeline.',
      btnText: 'Open Command Center →',
      route: '/command-center',
      icon: ShieldCheck
    };
  }

  // 7 Decision Pipeline Stages (User-friendly labels for main UI; technical module mappings in Know More view)
  const pipelineStages = [
    { code: 'M1', name: 'Scanner Ingestion & Signals', desc: 'Ingests raw security signals from ZAP, Nuclei, OpenVAS, and custom scanner telemetry.', status: totalAgents > 0 ? 'Ready' : 'Waiting', icon: Radio },
    { code: 'M2', name: 'Signal Normalization', desc: 'Translates multi-scanner finding payloads into standard security data contracts.', status: totalScanRuns > 0 ? 'Ready' : 'Waiting', icon: Layers },
    { code: 'M3', name: 'Intelligent Deduplication', desc: 'Correlates overlapping vulnerability signals across scanners by target endpoint and signature.', status: completedRuns.length > 0 ? 'Complete' : 'Ready', icon: GitMerge },
    { code: 'M4', name: 'Confidence Analysis', desc: 'Evaluates scanner consensus, signal weight, and historical false-positive patterns.', status: completedRuns.length > 0 ? 'Complete' : 'Ready', icon: ShieldCheck },
    { code: 'M5', name: 'Threat Intelligence Enrichment', desc: 'Enriches findings with live exploit probabilities (EPSS) and CISA Known Exploited Vulnerabilities (KEV).', status: totalScanRuns > 0 ? 'Ready' : 'Waiting', icon: Globe },
    { code: 'M6', name: 'Risk Scoring Engine', desc: 'Calculates dynamic 0-100 asset risk scores and SLA urgency countdown timers.', status: activeRuns.length > 0 ? 'Active' : (completedRuns.length > 0 ? 'Complete' : 'Waiting'), icon: BarChart3 },
    { code: 'M7', name: 'Explainable Remediation', desc: 'Generates interactive Risk DNA provenance graphs and analyst audit trail records.', status: completedRuns.length > 0 ? 'Output' : 'Waiting', icon: CheckCircle2 },
  ];

  // Derive Recent Activity items
  let recentActivities = [];
  if (scanRuns.length > 0) {
    scanRuns.slice(0, 3).forEach(run => {
      recentActivities.push({
        id: `run-${run.scan_run_id}`,
        text: `Scan run "${run.scan_run_id}" initiated (${(run.scanner_selections || []).join(', ') || 'Scanners'})`,
        time: formatTimeAgo(run.created_at),
        icon: Play,
        iconColor: '#3B82F6'
      });
    });
  }
  if (assets.length > 0) {
    assets.slice(0, 2).forEach(asset => {
      recentActivities.push({
        id: `asset-${asset.asset_id}`,
        text: `Asset "${asset.display_name || asset.target}" registered`,
        time: formatTimeAgo(asset.created_at),
        icon: Server,
        iconColor: '#10B981'
      });
    });
  }
  if (agents.length > 0) {
    agents.slice(0, 2).forEach(agent => {
      recentActivities.push({
        id: `agent-${agent.agent_id}`,
        text: `${agent.display_name} scanner connected`,
        time: formatTimeAgo(agent.created_at),
        icon: Radio,
        iconColor: '#7C3AED'
      });
    });
  }

  const NextActionIcon = nextAction.icon;

  return (
    <div className="ws-outer-wrapper" style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflowX: 'hidden' }}>
      {/* 1. Header / Hero Banner */}
      <div className="ws-hero-banner" style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="ws-hero-left" style={{ flex: '1 1 300px', minWidth: 0 }}>
          <span className="ws-section-tag">WORKSPACE</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', marginTop: '4px' }}>
            <h1 className="ws-hero-title" style={{ margin: 0 }}>
              {selectedOrg ? `${selectedOrg.display_name} Workspace` : 'Security Operations Workspace'}
            </h1>
            {organizations.length > 1 && (
              <select
                value={selectedOrg?.organization_id || ''}
                onChange={(e) => handleOrgChange(e.target.value)}
                className="ws-org-select"
              >
                {organizations.map(org => (
                  <option key={org.organization_id} value={org.organization_id}>
                    {org.display_name} ({org.environment || 'Production'})
                  </option>
                ))}
              </select>
            )}
          </div>
          <p className="ws-hero-desc">
            Configure your environment, connect scanners, and track the flow from security signals to prioritized risk.
          </p>
        </div>

        <div className="ws-status-card" style={{ flexShrink: 0 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <span className="ws-status-dot" style={{ background: statusBadge.color }} />
              <span className="ws-status-label" style={{ color: statusBadge.color }}>{statusBadge.label}</span>
            </div>
            <div className="ws-status-sub">{statusBadge.subText}</div>
          </div>
          <ShieldCheck size={28} color={statusBadge.color} style={{ opacity: 0.85 }} />
        </div>
      </div>

      {/* Loading Skeleton State */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: '#64748B' }}>
          <Activity className="animate-spin" size={32} style={{ margin: '0 auto 12px auto', color: '#4F46E5' }} />
          <p style={{ fontSize: '14px', fontWeight: '600' }}>Loading workspace telemetry & readiness status...</p>
        </div>
      ) : error ? (
        /* Error Alert State */
        <div className="ws-error-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <AlertCircle size={22} color="#DC2626" />
            <div>
              <strong style={{ fontSize: '15px' }}>Workspace status couldn't be loaded.</strong>
              <div style={{ fontSize: '13px', marginTop: '2px', opacity: 0.9 }}>{error}</div>
            </div>
          </div>
          <button
            type="button"
            className="ws-retry-btn"
            onClick={loadWorkspaceData}
          >
            <RefreshCw size={14} />
            <span>Retry</span>
          </button>
        </div>
      ) : (
        <>
          {/* 2. Primary 4-Summary Cards Grid */}
          <div className="ws-summary-grid">
            {/* Card 1: Assets */}
            <div className="ws-summary-card">
              <div className="ws-card-top">
                <div className="ws-card-icon-box" style={{ background: '#EEF2FF', color: '#4F46E5' }}>
                  <Server size={20} />
                </div>
                <div>
                  <div className="ws-card-number">{totalAssets}</div>
                  <div className="ws-card-title">Registered Assets</div>
                  <div className="ws-card-sub">
                    {totalAssets === 0 ? 'No assets registered yet' : `${activeAssets} Active • ${internalAssets} Internal`}
                  </div>
                </div>
              </div>
              <button type="button" className="ws-card-action" onClick={() => navigate('/asset-registry')}>
                <span>View Assets →</span>
              </button>
            </div>

            {/* Card 2: Scanners */}
            <div className="ws-summary-card">
              <div className="ws-card-top">
                <div className="ws-card-icon-box" style={{ background: '#ECFDF5', color: '#10B981' }}>
                  <Radio size={20} />
                </div>
                <div>
                  <div className="ws-card-number">{totalAgents}</div>
                  <div className="ws-card-title">Scanner Agents</div>
                  <div className="ws-card-sub">
                    {totalAgents === 0 ? 'No scanners connected' : `${connectedAgents} Connected • ${offlineAgents} Offline`}
                  </div>
                </div>
              </div>
              <button type="button" className="ws-card-action" onClick={() => navigate('/scanner-agents')}>
                <span>Manage Scanners →</span>
              </button>
            </div>

            {/* Card 3: Scan Runs */}
            <div className="ws-summary-card">
              <div className="ws-card-top">
                <div className="ws-card-icon-box" style={{ background: '#EFF6FF', color: '#2563EB' }}>
                  <Play size={20} />
                </div>
                <div>
                  <div className="ws-card-number">{totalScanRuns}</div>
                  <div className="ws-card-title">Scan Runs</div>
                  <div className="ws-card-sub">
                    {totalScanRuns === 0 ? 'No scan runs executed' : <><span>Active Scan Runs</span> • {lastRunTimeText}</>}
                  </div>
                </div>
              </div>
              <button type="button" className="ws-card-action" onClick={() => navigate('/scan-runs')}>
                <span>View Scan Runs →</span>
              </button>
            </div>

            {/* Card 4: Risk Pipeline */}
            <div className="ws-summary-card">
              <div className="ws-card-top">
                <div className="ws-card-icon-box" style={{ background: '#F5F3FF', color: '#7C3AED' }}>
                  <Layers size={20} />
                </div>
                <div>
                  <div className="ws-card-number" style={{ fontSize: '18px', letterSpacing: '-0.3px', fontWeight: '800' }}>Security Pipeline</div>
                  <div className="ws-card-title">
                    {totalScanRuns > 0 ? 'Pipeline Healthy' : 'Pipeline Ready'}
                  </div>
                  <div className="ws-card-sub">
                    {completedRuns.length > 0 ? 'Last processing successful' : 'Waiting for scan ingestion'}
                  </div>
                </div>
              </div>
              <button type="button" className="ws-card-action" onClick={() => navigate('/command-center')}>
                <span>View Command Center →</span>
              </button>
            </div>
          </div>

          {/* 3. Operational Readiness (4 Steps) */}
          <div className="ws-section-card">
            <div className="ws-section-header">
              <div>
                <div className="ws-section-title-row">
                  <h3 className="ws-section-heading">OPERATIONAL READINESS</h3>
                  <Info size={14} color="#94A3B8" title="Complete required setup steps before running security analysis" />
                </div>
                <div className="ws-section-sub">Complete the required setup before running security analysis. Click any step to configure.</div>
              </div>
            </div>

            <div className="ws-readiness-grid">
              {/* Step 01 */}
              <div
                className={`ws-step-card ${step1State === 'COMPLETE' ? 'active' : ''}`}
                onClick={() => navigate('/asset-registry')}
                style={{ cursor: 'pointer' }}
                title="Click to manage authorized target assets"
              >
                <div className="ws-step-top">
                  <span className="ws-step-num">01</span>
                  {step1State === 'COMPLETE' ? (
                    <span className="ws-step-status-badge complete"><Check size={12} /> Complete</span>
                  ) : (
                    <span className="ws-step-status-badge not_started">○ Not Started</span>
                  )}
                </div>
                <h4 className="ws-step-title">Register Assets</h4>
                <p className="ws-step-desc">Define the applications, APIs and infrastructure that may be scanned.</p>
              </div>

              {/* Step 02 */}
              <div
                className={`ws-step-card ${step2State === 'COMPLETE' ? 'active' : ''}`}
                onClick={() => navigate('/scanner-agents')}
                style={{ cursor: 'pointer' }}
                title="Click to configure security scanner agents"
              >
                <div className="ws-step-top">
                  <span className="ws-step-num">02</span>
                  {step2State === 'COMPLETE' ? (
                    <span className="ws-step-status-badge complete"><Check size={12} /> Complete</span>
                  ) : (
                    <span className="ws-step-status-badge not_started">○ Not Started</span>
                  )}
                </div>
                <h4 className="ws-step-title">Connect Scanner Agents</h4>
                <p className="ws-step-desc">Configure approved security scanners and verify connectivity.</p>
              </div>

              {/* Step 03 */}
              <div
                className={`ws-step-card ${step3State === 'IN_PROGRESS' || step3State === 'COMPLETE' ? 'active' : ''}`}
                onClick={() => navigate('/scan-runs')}
                style={{ cursor: 'pointer' }}
                title="Click to launch or ingest scan runs"
              >
                <div className="ws-step-top">
                  <span className="ws-step-num">03</span>
                  {step3State === 'IN_PROGRESS' ? (
                    <span className="ws-step-status-badge in_progress">● In Progress</span>
                  ) : step3State === 'COMPLETE' ? (
                    <span className="ws-step-status-badge complete"><Check size={12} /> Complete</span>
                  ) : (
                    <span className="ws-step-status-badge not_started">○ Not Started</span>
                  )}
                </div>
                <h4 className="ws-step-title">Run Authorized Scans</h4>
                <p className="ws-step-desc">Launch or ingest approved scan activity against registered targets.</p>
              </div>

              {/* Step 04 */}
              <div
                className={`ws-step-card ${step4State === 'COMPLETE' || step4State === 'IN_PROGRESS' ? 'active' : ''}`}
                onClick={() => navigate('/command-center')}
                style={{ cursor: 'pointer' }}
                title="Click to view prioritized security risk decisions"
              >
                <div className="ws-step-top">
                  <span className="ws-step-num">04</span>
                  {step4State === 'COMPLETE' ? (
                    <span className="ws-step-status-badge complete"><Check size={12} /> Complete</span>
                  ) : step4State === 'IN_PROGRESS' ? (
                    <span className="ws-step-status-badge in_progress">● In Progress</span>
                  ) : (
                    <span className="ws-step-status-badge not_started">○ Not Started</span>
                  )}
                </div>
                <h4 className="ws-step-title">Analyze Prioritized Risk</h4>
                <p className="ws-step-desc">Process normalized findings through the RizIntel intelligence pipeline.</p>
              </div>
            </div>

            <div style={{ marginTop: '14px', fontSize: '11.5px', color: '#64748B', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Info size={13} color="#94A3B8" />
              <span>Complete the steps in order to generate prioritized and explainable remediation decisions.</span>
            </div>
          </div>

          {/* 4. Split Row: Next Best Action & Workspace Context */}
          <div className="ws-split-row">
            {/* Left Card: Next Best Action */}
            <div className="ws-next-action-card">
              <div className="ws-next-action-content">
                <span className="ws-next-action-tag">NEXT BEST ACTION</span>
                <h3 className="ws-next-action-title">{nextAction.title}</h3>
                <p className="ws-next-action-desc">{nextAction.desc}</p>

                <button
                  type="button"
                  className="ws-next-action-btn"
                  onClick={() => navigate(nextAction.route)}
                >
                  <span>{nextAction.btnText}</span>
                </button>
              </div>

              <div className="ws-next-action-graphic">
                <NextActionIcon size={32} />
              </div>
            </div>

            {/* Right Card: Workspace Context */}
            <div className="ws-context-card">
              <div style={{ fontSize: '12px', fontWeight: '800', letterSpacing: '0.7px', color: 'var(--text-secondary, #334155)', textTransform: 'uppercase', marginBottom: '4px' }}>
                WORKSPACE CONTEXT
              </div>

              <div className="ws-context-row">
                <span className="ws-context-label"><Building2 size={15} /> Organization</span>
                <span className="ws-context-val">{selectedOrg?.display_name || 'SVCE Security Lab'}</span>
              </div>

              <div className="ws-context-row">
                <span className="ws-context-label"><Compass size={15} /> Environment</span>
                <span className="ws-context-val">{selectedOrg?.environment || 'Production'}</span>
              </div>

              <div className="ws-context-row">
                <span className="ws-context-label"><Globe size={15} /> Region</span>
                <span className="ws-context-val">{selectedOrg?.region || 'Local'}</span>
              </div>

              <div className="ws-context-row">
                <span className="ws-context-label"><User size={15} /> Current Role</span>
                <span className="ws-context-val role-badge">
                  {currentUser?.role ? currentUser.role.replace('_', ' ') : 'Security Lead'}
                </span>
              </div>

              <div className="ws-context-row">
                <span className="ws-context-label"><Key size={15} /> Workspace ID</span>
                <span className="ws-context-val">{selectedOrg?.organization_id || 'RIZ-WS-7F3A'}</span>
              </div>
            </div>
          </div>

          {/* 5. Security Decision Pipeline */}
          <div className="ws-section-card">
            <div className="ws-section-header" style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div className="ws-section-title-row">
                  <h3 className="ws-section-heading">SECURITY DECISION PIPELINE</h3>
                  <Info size={14} color="#94A3B8" title="RizIntel 7-stage normalized risk intelligence pipeline" />
                </div>
                <div className="ws-section-sub">
                  RizIntel converts multi-scanner signals into deduplicated, context-aware and explainable remediation decisions.
                </div>
              </div>

              {/* Know More / Technical Deep Dive Toggle */}
              <button
                type="button"
                className={`ws-tech-toggle-btn ${showTechDetails ? 'active' : ''}`}
                onClick={() => setShowTechDetails(!showTechDetails)}
              >
                <Layers size={14} />
                <span>{showTechDetails ? 'Hide Technical Architecture' : 'Know More / Deep Dive'}</span>
              </button>
            </div>

            {/* Main Stage Cards (User-Friendly Labels) */}
            <div className="ws-pipeline-grid">
              {pipelineStages.map((stage) => {
                const StageIcon = stage.icon;
                const isStageActive = stage.status !== 'Waiting';
                return (
                  <div key={stage.code} className={`ws-pipeline-card ${isStageActive ? 'active' : ''}`} title={stage.desc}>
                    <div className="ws-pipeline-icon-box">
                      <StageIcon size={16} />
                    </div>
                    <span className="ws-pipeline-name">{stage.name}</span>
                    <span className={`ws-pipeline-status ${stage.status === 'Waiting' ? 'waiting' : ''}`}>
                      {stage.status}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Collapsible Technical Architecture Deep Dive (M1-M7 System Mappings) */}
            {showTechDetails && (
              <div className="ws-tech-details-container">
                <div className="ws-tech-details-title">
                  Technical Architecture & Internal Module Mappings (M1–M7)
                </div>
                <p className="ws-tech-details-desc">
                  Below is the technical specification mapping each user-facing pipeline stage to its corresponding system module contract:
                </p>
                <div className="ws-tech-modules-grid">
                  {pipelineStages.map((stage) => (
                    <div key={stage.code} className="ws-tech-module-card">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                        <span className="ws-tech-code-badge">
                          {stage.code}
                        </span>
                        <strong className="ws-tech-module-name">{stage.name}</strong>
                      </div>
                      <p className="ws-tech-module-desc">{stage.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 6. Recent Activity Section */}
          <div className="ws-section-card">
            <div className="ws-section-header">
              <h3 className="ws-section-heading">RECENT WORKSPACE ACTIVITY</h3>
              <button
                type="button"
                onClick={() => navigate('/scan-runs')}
                style={{ background: 'none', border: 'none', color: '#4F46E5', fontSize: '12px', fontWeight: '600', cursor: 'pointer' }}
              >
                View All →
              </button>
            </div>

            {recentActivities.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 0', color: '#94A3B8' }}>
                <p style={{ fontSize: '13.5px', fontWeight: '500', margin: '0 0 4px 0', color: '#64748B' }}>No workspace activity yet.</p>
                <p style={{ fontSize: '12px', margin: 0 }}>Register an asset or connect a scanner to begin.</p>
              </div>
            ) : (
              <div className="ws-activity-list">
                {recentActivities.map(act => {
                  const ActIcon = act.icon;
                  return (
                    <div key={act.id} className="ws-activity-item">
                      <div className="ws-activity-left">
                        <ActIcon size={16} color={act.iconColor} />
                        <span className="ws-activity-text">{act.text}</span>
                      </div>
                      <span className="ws-activity-time">{act.time}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
