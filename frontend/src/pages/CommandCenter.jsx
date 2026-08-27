import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useFindings } from '../hooks/useFindings';
import { useDashboard } from '../hooks/useDashboard';
import { getScanRunFindings, getRuntimeStatus, RUNTIME_STATUS, getCurrentUser } from '../services/findingsService';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import {
  Shield, Flame, TrendingUp, AlertTriangle,
  Clock, Globe, Server, ArrowRight, Check,
  Layers, Target, Zap, ChevronLeft, ChevronRight,
  Search, RefreshCw, AlertCircle, X, Info,
  CheckCircle2, ShieldAlert, Activity
} from 'lucide-react';

/* ─── SLA helpers ───────────────────────────────────────────────────────── */

function parseSlaRemaining(slaStatus, slaDueAt) {
  if (!slaDueAt) return null;
  const now = Date.now();
  const due = new Date(slaDueAt).getTime();
  if (isNaN(due)) return null;
  const diffMs = due - now;
  const status = (slaStatus || '').toUpperCase();
  if (status === 'BREACHED' || diffMs < 0) {
    const abs = Math.abs(diffMs);
    const h = Math.floor(abs / 3600000);
    const m = Math.floor((abs % 3600000) / 60000);
    return { breached: true, label: h > 0 ? `Breached by ${h}h ${m}m` : 'Breached' };
  }
  const h = Math.floor(diffMs / 3600000);
  const m = Math.floor((diffMs % 3600000) / 60000);
  const d = Math.floor(diffMs / 86400000);
  if (d >= 2) return { breached: false, atRisk: false, label: `${d}d remaining` };
  if (h >= 1) return { breached: false, atRisk: status === 'AT_RISK', label: `${h}h ${m}m remaining` };
  return { breached: false, atRisk: true, label: `${m}m remaining` };
}

function SlaTag({ slaStatus, slaDueAt }) {
  const info = parseSlaRemaining(slaStatus, slaDueAt);
  const status = (slaStatus || '').toUpperCase();
  if (status === 'BREACHED' || info?.breached) {
    return (
      <span className="cc-sla-pill cc-sla-breached">
        <Clock size={10} aria-hidden="true" /> {info?.label || 'SLA Breached'}
      </span>
    );
  }
  if (status === 'AT_RISK' || info?.atRisk) {
    return (
      <span className="cc-sla-pill cc-sla-atrisk">
        <AlertTriangle size={10} aria-hidden="true" /> {info?.label || 'SLA At Risk'}
      </span>
    );
  }
  if (info?.label) {
    return (
      <span className="cc-sla-pill cc-sla-healthy">
        <Check size={10} aria-hidden="true" /> {info.label}
      </span>
    );
  }
  return (
    <span className="cc-sla-pill cc-sla-healthy">
      <Check size={10} aria-hidden="true" /> On Track
    </span>
  );
}

/* ─── Severity helpers ───────────────────────────────────────────────────── */

function normSeverity(f) {
  const lvl = (f.risk_level || '').toUpperCase();
  if (lvl === 'CRITICAL' || lvl === 'HIGH' || lvl === 'MEDIUM' || lvl === 'LOW') return lvl;
  const score = f.risk_score ?? 0;
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

const SEV_COLOR = { CRITICAL: '#EF4444', HIGH: '#F97316', MEDIUM: '#EAB308', LOW: '#10B981' };

function SeverityBadge({ severity }) {
  const sev = (severity || 'MEDIUM').toUpperCase();
  const color = SEV_COLOR[sev] || '#64748B';
  return (
    <span
      className="cc-sev-badge"
      style={{ background: `${color}1A`, color, borderColor: `${color}50` }}
    >
      {sev}
    </span>
  );
}

/* ─── Pipeline stage names (customer-facing only) ─────────────────────── */

const PIPELINE_STAGES = [
  'Scanner Signals',
  'Normalization',
  'Intelligent Deduplication',
  'Confidence Analysis',
  'Threat Intelligence',
  'Risk Scoring',
  'Explainability',
  'SLA & Remediation',
];

function PipelineHealth({ runtimeStatus }) {
  const isLive = runtimeStatus === RUNTIME_STATUS.LIVE;
  const isConnecting = runtimeStatus === RUNTIME_STATUS.CONNECTING;
  const isFallback = runtimeStatus === RUNTIME_STATUS.FALLBACK || runtimeStatus === RUNTIME_STATUS.MOCK;
  const overallLabel = isLive ? 'Operational' : isConnecting ? 'Connecting…' : isFallback ? 'Using Cached Data' : 'Unavailable';
  const overallColor = isLive ? '#10B981' : isConnecting ? '#F59E0B' : '#94A3B8';

  return (
    <div className="cc-panel">
      <div className="cc-panel-header">
        <div className="cc-panel-title">
          <Activity size={15} style={{ color: '#6366F1' }} aria-hidden="true" />
          Pipeline Health
        </div>
        <span style={{ fontSize: 12, fontWeight: 600, color: overallColor }}>
          ● {overallLabel}
        </span>
      </div>
      <div className="cc-pipeline-stages">
        {PIPELINE_STAGES.map(stage => (
          <div key={stage} className="cc-stage-item">
            <span className="cc-stage-dot" style={{ background: overallColor }} aria-hidden="true" />
            <span className="cc-stage-label">{stage}</span>
            <span className="cc-stage-status" style={{ color: overallColor }}>
              {isLive ? 'Healthy' : isConnecting ? 'Connecting…' : 'Unavailable'}
            </span>
          </div>
        ))}
      </div>
      {isFallback && (
        <p className="cc-pipeline-note">
          Live pipeline data unavailable. Showing last known findings.
        </p>
      )}
    </div>
  );
}

/* ─── Skeleton ───────────────────────────────────────────────────────────── */

function SkeletonCard() {
  return (
    <div className="cc-skeleton-card" aria-hidden="true">
      <div className="cc-sk-line" style={{ width: '40%', height: 12, marginBottom: 8 }} />
      <div className="cc-sk-line" style={{ width: '80%', height: 18, marginBottom: 6 }} />
      <div className="cc-sk-line" style={{ width: '60%', height: 12, marginBottom: 12 }} />
      <div style={{ display: 'flex', gap: 8 }}>
        <div className="cc-sk-line" style={{ width: 60, height: 28, borderRadius: 6 }} />
        <div className="cc-sk-line" style={{ width: 80, height: 28, borderRadius: 6 }} />
      </div>
    </div>
  );
}

/* ─── Main ───────────────────────────────────────────────────────────────── */

const PAGE_SIZE = 5;

export default function CommandCenter() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const scanRunId = searchParams.get('scan_run_id');
  const orgId     = searchParams.get('org_id');

  /* Scan-run scoped data */
  const [scopedData,    setScopedData]    = useState(null);
  const [scopedLoading, setScopedLoading] = useState(!!scanRunId);
  const [scopedError,   setScopedError]   = useState(null);

  /* Global data */
  const { findings: globalFindings, loading: findingsLoading, error: findingsError } = useFindings();
  const { summary:  globalSummary,  loading: summaryLoading,  error: summaryError  } = useDashboard();

  /* Runtime status */
  const [runtimeStatus, setRuntimeStatus] = useState(() => getRuntimeStatus());

  /* UI filters */
  const [search,        setSearch]        = useState('');
  const [filterSev,     setFilterSev]     = useState('ALL');
  const [filterSla,     setFilterSla]     = useState('ALL');
  const [filterStatus,  setFilterStatus]  = useState('ALL');
  const [page,          setPage]          = useState(1);
  const [refreshKey,    setRefreshKey]    = useState(0);

  const currentUser = useMemo(() => getCurrentUser(), []);

  /* Load scoped findings */
  useEffect(() => {
    if (!scanRunId || !orgId) { setScopedLoading(false); return; }
    let cancelled = false;
    setScopedLoading(true);
    setScopedError(null);
    getScanRunFindings(orgId, scanRunId)
      .then(data => { if (!cancelled) setScopedData(data); })
      .catch(err => { if (!cancelled) setScopedError(err.message || `Cannot load results for ${scanRunId}`); })
      .finally(() => { if (!cancelled) setScopedLoading(false); });
    return () => { cancelled = true; };
  }, [scanRunId, orgId, refreshKey]);

  /* Track runtime status */
  useEffect(() => {
    const handler = e => setRuntimeStatus(e.detail?.status || getRuntimeStatus());
    window.addEventListener('rizintel-runtimestatus-change', handler);
    return () => window.removeEventListener('rizintel-runtimestatus-change', handler);
  }, []);

  /* Reset page when filters change */
  useEffect(() => setPage(1), [search, filterSev, filterSla, filterStatus]);

  const isScoped  = !!scanRunId;
  const isLoading = isScoped ? scopedLoading : (findingsLoading || summaryLoading);
  const loadError = isScoped ? scopedError   : (findingsError || summaryError);

  const rawFindings = isScoped ? (scopedData?.findings || []) : (globalFindings || []);
  const summaryData = isScoped
    ? (scopedData?.summary?.summary ?? scopedData?.summary ?? {})
    : (globalSummary?.summary ?? {});
  const scanRunMeta = isScoped ? scopedData : null;

  /* Summary counts derived accurately and consistently from data */
  const stats = useMemo(() => {
    let critical = 0, high = 0, medium = 0, low = 0, slaBreached = 0, slaAtRisk = 0;
    for (const f of rawFindings) {
      const sev = normSeverity(f);
      if (sev === 'CRITICAL') critical++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') medium++;
      else low++;
      const s = (f.workflow?.sla_status || '').toUpperCase();
      if (s === 'BREACHED') slaBreached++;
      else if (s === 'AT_RISK') slaAtRisk++;
    }

    const hasSummaryBreakdown = summaryData && (
      (summaryData.critical ?? 0) > 0 ||
      (summaryData.high ?? 0) > 0 ||
      (summaryData.medium ?? 0) > 0 ||
      (summaryData.low ?? 0) > 0
    );

    const sCrit = hasSummaryBreakdown ? summaryData.critical : critical;
    const sHigh = hasSummaryBreakdown ? summaryData.high : high;
    const sMed = hasSummaryBreakdown ? summaryData.medium : medium;
    const sLow = hasSummaryBreakdown ? summaryData.low : low;
    const sBreached = (summaryData?.sla_breaches != null && summaryData.sla_breaches > 0) ? summaryData.sla_breaches : slaBreached;
    const sAtRisk = (summaryData?.sla_at_risk != null && summaryData.sla_at_risk > 0) ? summaryData.sla_at_risk : slaAtRisk;
    const sActive = (summaryData?.unique_findings != null && summaryData.unique_findings > 0)
      ? summaryData.unique_findings
      : (summaryData?.actionable_findings != null && summaryData.actionable_findings > 0)
        ? summaryData.actionable_findings
        : (sCrit + sHigh + sMed + sLow > 0 ? (sCrit + sHigh + sMed + sLow) : rawFindings.length);

    return {
      critical: sCrit,
      high: sHigh,
      medium: sMed,
      low: sLow,
      slaBreached: sBreached,
      slaAtRisk: sAtRisk,
      active: sActive,
    };
  }, [rawFindings, summaryData]);

  /* Donut data from real stats */
  const donutData = useMemo(() => {
    const total = stats.critical + stats.high + stats.medium + stats.low;
    const pct = n => total > 0 ? `${Math.round((n / total) * 100)}%` : '0%';
    return [
      { name: 'Critical', value: stats.critical, color: '#EF4444', pct: pct(stats.critical) },
      { name: 'High',     value: stats.high,     color: '#F97316', pct: pct(stats.high) },
      { name: 'Medium',   value: stats.medium,   color: '#EAB308', pct: pct(stats.medium) },
      { name: 'Low',      value: stats.low,      color: '#10B981', pct: pct(stats.low) },
    ];
  }, [stats]);

  /* SLA overview derived consistently from real stats */
  const slaOverview = useMemo(() => {
    const breached = stats.slaBreached;
    const atRisk = stats.slaAtRisk;
    const healthy = Math.max(0, stats.active - breached - atRisk);
    return { BREACHED: breached, AT_RISK: atRisk, HEALTHY: healthy };
  }, [stats]);

  /* Filtered findings */
  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rawFindings.filter(f => {
      if (q) {
        const n = (f.vulnerability_name || '').toLowerCase();
        const c = (f.cve_id || '').toLowerCase();
        const a = (f.detail?.asset_context?.asset_name || f.asset_id || '').toLowerCase();
        const h = (f.target_host || f.host || '').toLowerCase();
        if (!n.includes(q) && !c.includes(q) && !a.includes(q) && !h.includes(q)) return false;
      }
      if (filterSev !== 'ALL' && normSeverity(f) !== filterSev) return false;
      if (filterSla !== 'ALL') {
        const s = (f.workflow?.sla_status || 'ON_TRACK').toUpperCase();
        if (filterSla === 'HEALTHY'  && (s === 'BREACHED' || s === 'AT_RISK')) return false;
        if (filterSla === 'AT_RISK'  && s !== 'AT_RISK')  return false;
        if (filterSla === 'BREACHED' && s !== 'BREACHED') return false;
      }
      if (filterStatus !== 'ALL') {
        const s = (f.workflow?.status || '').toUpperCase();
        if (s !== filterStatus) return false;
      }
      return true;
    });
  }, [rawFindings, search, filterSev, filterSla, filterStatus]);

  const totalPages   = Math.max(1, Math.ceil(filteredFindings.length / PAGE_SIZE));
  const pagedFindings = filteredFindings.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const hasFilters   = search || filterSev !== 'ALL' || filterSla !== 'ALL' || filterStatus !== 'ALL';

  function resetFilters() {
    setSearch(''); setFilterSev('ALL'); setFilterSla('ALL'); setFilterStatus('ALL');
  }

  function handleRefresh() {
    setRefreshKey(k => k + 1);
    if (!isScoped) window.dispatchEvent(new CustomEvent('rizintel-datamode-change'));
  }

  /* Next Best Action (deterministic) */
  const nba = useMemo(() => {
    if (!rawFindings.length) return null;
    const breached = rawFindings.filter(f => (f.workflow?.sla_status || '').toUpperCase() === 'BREACHED');
    if (breached.length) {
      const top = breached[0];
      const asset = top.detail?.asset_context?.asset_name || top.asset_id;
      return {
        text: breached.length === 1
          ? `${top.vulnerability_name} affecting ${asset} has breached its SLA.`
          : `${breached.length} findings have breached SLA.`,
        findingId: top.finding_id,
      };
    }
    const atRisk = rawFindings.filter(f => (f.workflow?.sla_status || '').toUpperCase() === 'AT_RISK');
    if (atRisk.length) {
      const top = atRisk[0];
      const asset = top.detail?.asset_context?.asset_name || top.asset_id;
      return {
        text: atRisk.length === 1
          ? `${top.vulnerability_name} affecting ${asset} is approaching SLA.`
          : `${atRisk.length} findings are approaching SLA.`,
        findingId: top.finding_id,
      };
    }
    const crits = rawFindings.filter(f => normSeverity(f) === 'CRITICAL');
    if (crits.length) {
      const top = crits[0];
      const asset = top.detail?.asset_context?.asset_name || top.asset_id;
      const explanation = top.detail?.explanation?.management;
      return {
        text: explanation
          ? `Investigate the critical ${top.vulnerability_name} affecting ${asset}. ${explanation}`
          : `Investigate the critical ${top.vulnerability_name} affecting ${asset}.`,
        findingId: top.finding_id,
      };
    }
    const top = rawFindings[0];
    return top ? { text: `Review the highest-priority finding: ${top.vulnerability_name}.`, findingId: top.finding_id } : null;
  }, [rawFindings]);

  const totalDonut = donutData.reduce((s, d) => s + d.value, 0);

  /* ── LOADING ────────────────────────────────────────────────────────── */
  if (isLoading) {
    return (
      <div className="cc-page-wrapper">
        <div className="cc-page-header">
          <div className="cc-page-header-title-row">
            <h1 className="cc-page-title">Command Center</h1>
          </div>
          <p className="cc-page-subtitle">Loading security findings…</p>
        </div>
        <div className="cc-summary-row">
          {[0,1,2,3,4].map(i => (
            <div key={i} className="cc-summary-card cc-skeleton-card" aria-hidden="true">
              <div className="cc-sk-line" style={{ width: '60%', height: 12, marginBottom: 6 }} />
              <div className="cc-sk-line" style={{ width: '40%', height: 28, marginBottom: 4 }} />
              <div className="cc-sk-line" style={{ width: '80%', height: 10 }} />
            </div>
          ))}
        </div>
        <div className="cc-main-grid">
          <div className="cc-priority-panel">
            <div className="cc-panel">
              <div className="cc-panel-title" style={{ marginBottom: 16 }}>Priority Attention</div>
              {[0,1,2,3].map(i => <SkeletonCard key={i} />)}
            </div>
          </div>
          <div className="cc-sidebar">
            <SkeletonCard /><SkeletonCard />
          </div>
        </div>
      </div>
    );
  }

  /* ── ERROR ──────────────────────────────────────────────────────────── */
  if (loadError && rawFindings.length === 0) {
    return (
      <div className="cc-page-wrapper">
        <div className="cc-error-state" role="alert">
          <AlertCircle size={40} color="#EF4444" aria-hidden="true" />
          <h2>Unable to load Command Center</h2>
          <p>We couldn't retrieve the latest security findings. Please try again.</p>
          <button className="cc-retry-btn" onClick={handleRefresh} id="cc-retry-btn">
            <RefreshCw size={14} aria-hidden="true" /> Retry
          </button>
        </div>
      </div>
    );
  }

  /* ── MAIN RENDER ────────────────────────────────────────────────────── */
  return (
    <div className="cc-page-wrapper">

      {/* PAGE HEADER */}
      <div className="cc-page-header">
        <div className="cc-page-header-title-row">
          <h1 className="cc-page-title">Command Center</h1>
          <span className={`cc-runtime-pill ${runtimeStatus === RUNTIME_STATUS.LIVE ? 'cc-runtime-live' : 'cc-runtime-cached'}`}>
            <span className="cc-runtime-dot" aria-hidden="true" />
            {runtimeStatus === RUNTIME_STATUS.LIVE ? 'Pipeline Live' : runtimeStatus === RUNTIME_STATUS.MOCK ? 'Mock Mode' : 'Cached Data'}
          </span>
        </div>
        <p className="cc-page-subtitle">
          Prioritize security risk, monitor remediation urgency, and investigate the findings that matter most.
        </p>
      </div>

      {/* SCAN RUN SCOPE BANNER */}
      {isScoped && scanRunMeta && (
        <div className="cc-scope-banner" role="status">
          <div className="cc-scope-banner-left">
            <Shield size={14} color="#6366F1" aria-hidden="true" />
            <div>
              <div className="cc-scope-banner-title">
                Viewing results for Scan Run <strong>{scanRunId}</strong>
              </div>
              {scanRunMeta.completed_at && (
                <div className="cc-scope-banner-sub">
                  Completed on {new Date(scanRunMeta.completed_at).toLocaleString('en-GB', {
                    day: '2-digit', month: 'short', year: 'numeric',
                    hour: '2-digit', minute: '2-digit'
                  })}
                </div>
              )}
            </div>
          </div>
          <button
            className="cc-scope-clear-btn"
            id="cc-clear-filter-btn"
            onClick={() => {
              const next = new URLSearchParams(searchParams);
              next.delete('scan_run_id');
              next.delete('org_id');
              setSearchParams(next);
              setScopedData(null);
            }}
            aria-label="Clear scan run filter"
          >
            Clear Filter <X size={12} aria-hidden="true" />
          </button>
        </div>
      )}

      {isScoped && scopedError && (
        <div className="cc-scope-error" role="alert">
          <AlertCircle size={14} aria-hidden="true" /> {scopedError}
        </div>
      )}

      {/* SUMMARY CARDS */}
      <div className="cc-summary-row" role="region" aria-label="Security summary metrics">
        <div className="cc-summary-card cc-sum-critical">
          <div className="cc-sum-icon"><ShieldAlert size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${stats.critical} critical findings`}>{stats.critical}</div>
          <div className="cc-sum-label">Critical Risk</div>
          <div className="cc-sum-sub">Active critical findings</div>
        </div>
        <div className="cc-summary-card cc-sum-high">
          <div className="cc-sum-icon"><AlertTriangle size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${stats.high} high findings`}>{stats.high}</div>
          <div className="cc-sum-label">High Risk</div>
          <div className="cc-sum-sub">Active high findings</div>
        </div>
        <div className="cc-summary-card cc-sum-sla-risk">
          <div className="cc-sum-icon"><Clock size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${stats.slaAtRisk} findings at SLA risk`}>{stats.slaAtRisk}</div>
          <div className="cc-sum-label">SLA At Risk</div>
          <div className="cc-sum-sub">Due within 24 hours</div>
        </div>
        <div className="cc-summary-card cc-sum-sla-breach">
          <div className="cc-sum-icon"><AlertCircle size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${stats.slaBreached} findings breached SLA`}>{stats.slaBreached}</div>
          <div className="cc-sum-label">SLA Breached</div>
          <div className="cc-sum-sub">Past due</div>
        </div>
        <div className="cc-summary-card cc-sum-active">
          <div className="cc-sum-icon"><Layers size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${stats.active} active findings`}>{stats.active}</div>
          <div className="cc-sum-label">Active Findings</div>
          <div className="cc-sum-sub">All open findings</div>
        </div>
      </div>

      {/* MAIN GRID */}
      <div className="cc-main-grid">

        {/* LEFT: Priority Attention */}
        <div className="cc-priority-panel">
          <div className="cc-panel">
            <div className="cc-panel-header">
              <div>
                <div className="cc-panel-title">
                  <Target size={15} style={{ color: '#6366F1' }} aria-hidden="true" />
                  Priority Attention
                </div>
                <p className="cc-panel-subtitle">
                  Findings requiring immediate analyst review, ordered by risk and remediation urgency.
                </p>
              </div>
            </div>

            {/* Filter bar */}
            <div className="cc-filter-bar" role="search" aria-label="Filter priority findings">
              <div className="cc-search-wrap">
                <Search size={14} className="cc-search-icon" aria-hidden="true" />
                <input
                  id="cc-search-input"
                  className="cc-search-input"
                  type="text"
                  placeholder="Search by finding, CVE, asset or host…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  aria-label="Search findings"
                />
                {search && (
                  <button className="cc-search-clear" onClick={() => setSearch('')} aria-label="Clear search">
                    <X size={12} aria-hidden="true" />
                  </button>
                )}
              </div>
              <label htmlFor="cc-filter-sev" className="cc-sr-only">Severity</label>
              <select id="cc-filter-sev" className="cc-filter-select" value={filterSev} onChange={e => setFilterSev(e.target.value)} aria-label="Filter by severity">
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <label htmlFor="cc-filter-sla" className="cc-sr-only">SLA Status</label>
              <select id="cc-filter-sla" className="cc-filter-select" value={filterSla} onChange={e => setFilterSla(e.target.value)} aria-label="Filter by SLA status">
                <option value="ALL">All SLA States</option>
                <option value="HEALTHY">Healthy</option>
                <option value="AT_RISK">At Risk</option>
                <option value="BREACHED">Breached</option>
              </select>
              <label htmlFor="cc-filter-status" className="cc-sr-only">Status</label>
              <select id="cc-filter-status" className="cc-filter-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} aria-label="Filter by status">
                <option value="ALL">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="IN_PROGRESS">In Progress</option>
              </select>
              <button id="cc-refresh-btn" className="cc-refresh-btn" onClick={handleRefresh} aria-label="Refresh findings">
                <RefreshCw size={14} aria-hidden="true" /> Refresh
              </button>
            </div>

            {/* Empty: no findings at all */}
            {rawFindings.length === 0 && (
              <div className="cc-empty-state" role="status">
                <CheckCircle2 size={40} color="#94A3B8" aria-hidden="true" />
                <h3>No prioritized findings yet</h3>
                <p>Complete an authorized security scan to generate prioritized and explainable security findings.</p>
                {currentUser?.config?.canDecide ? (
                  <button className="cc-empty-action-btn" onClick={() => navigate('/scan-runs')} id="cc-create-scan-btn">
                    Create Scan Run
                  </button>
                ) : (
                  <p className="cc-empty-viewer-note">
                    Prioritized findings will appear here after an authorized security scan is completed.
                  </p>
                )}
              </div>
            )}

            {/* Empty: findings exist but filters exclude all */}
            {rawFindings.length > 0 && filteredFindings.length === 0 && (
              <div className="cc-empty-filtered" role="status">
                <Search size={32} color="#94A3B8" aria-hidden="true" />
                <p>No findings match your filters.</p>
                <button className="cc-reset-filters-btn" onClick={resetFilters} id="cc-reset-filters-btn">
                  Reset Filters
                </button>
              </div>
            )}

            {/* Finding cards */}
            {pagedFindings.map((item, idx) => {
              const rank = (page - 1) * PAGE_SIZE + idx + 1;
              const sev  = normSeverity(item);
              const ti   = item.detail?.threat_intelligence || {};
              const sc   = item.detail?.scanner_consensus   || {};
              const fc   = item.detail?.finding_confidence  || {};
              const assetName = item.detail?.asset_context?.asset_name || item.asset_id || 'Unmapped Asset';
              const explanation = item.detail?.explanation?.management;
              const isCrit = sev === 'CRITICAL';

              return (
                <div
                  key={item.finding_id || idx}
                  className={`cc-finding-card ${isCrit ? 'cc-fc-crit' : sev === 'HIGH' ? 'cc-fc-high' : 'cc-fc-med'}`}
                  role="article"
                  aria-label={`Priority ${rank}: ${item.vulnerability_name}`}
                >
                  {/* Top bar */}
                  <div className="cc-fc-topbar">
                    <span className={`cc-rank-badge ${isCrit ? 'cc-rank-crit' : 'cc-rank-high'}`}>#{rank}</span>
                    <SeverityBadge severity={sev} />
                    {item.cve_id && <span className="cc-cve-pill">{item.cve_id}</span>}
                    {ti.kev_listed && (
                      <span className="cc-kev-badge" title="CISA Known Exploited Vulnerability">
                        <Flame size={10} aria-hidden="true" /> KEV
                      </span>
                    )}
                  </div>

                  {/* Name + asset */}
                  <div className="cc-fc-name">{item.vulnerability_name || '—'}</div>
                  <div className="cc-fc-asset-row">
                    {item.internet_exposure
                      ? <Globe size={12} color="#3B82F6" aria-hidden="true" />
                      : <Server size={12} color="#64748B" aria-hidden="true" />}
                    <span className="cc-fc-asset">{assetName}</span>
                    {(item.target_host || item.host) && (
                      <span className="cc-fc-host">· {item.target_host || item.host}</span>
                    )}
                  </div>

                  {/* Metrics */}
                  <div className="cc-fc-metrics">
                    {item.risk_score != null && (
                      <div className="cc-metric">
                        <span className="cc-metric-lbl">Risk Score</span>
                        <span className={`cc-risk-score ${isCrit ? 'cc-rs-crit' : 'cc-rs-high'}`}>{item.risk_score}</span>
                      </div>
                    )}
                    {fc.score != null && (
                      <div className="cc-metric">
                        <span className="cc-metric-lbl">Confidence</span>
                        <span className="cc-metric-val">{Math.round(fc.score * 100)}%</span>
                      </div>
                    )}
                    <div className="cc-metric">
                      <span className="cc-metric-lbl">SLA</span>
                      <SlaTag slaStatus={item.workflow?.sla_status} slaDueAt={item.workflow?.sla_due_at} />
                    </div>
                    {sc.detected_by_count != null && (
                      <div className="cc-metric">
                        <span className="cc-metric-lbl">Sources</span>
                        <span className="cc-metric-val">{sc.detected_by_count} Scanner{sc.detected_by_count !== 1 ? 's' : ''}</span>
                      </div>
                    )}
                  </div>

                  {/* TI badges */}
                  {(ti.epss_score != null || ti.exploit_available || item.internet_exposure != null || ti.cvss_score != null) && (
                    <div className="cc-fc-ti-row">
                      {ti.epss_score != null && (
                        <span className="cc-ti-badge cc-ti-epss" title={`EPSS ${Math.round(ti.epss_score*100)}%`}>
                          <TrendingUp size={10} aria-hidden="true" /> EPSS {Math.round(ti.epss_score*100)}%
                        </span>
                      )}
                      {ti.exploit_available && (
                        <span className="cc-ti-badge cc-ti-exploit" title="Public exploit available">
                          <Zap size={10} aria-hidden="true" /> Exploit Available
                        </span>
                      )}
                      {item.internet_exposure === true && (
                        <span className="cc-ti-badge cc-ti-exposure" title="Internet-facing asset">
                          <Globe size={10} aria-hidden="true" /> Internet-Facing
                        </span>
                      )}
                      {ti.cvss_score != null && (
                        <span className="cc-ti-badge cc-ti-cvss" title={`CVSS ${ti.cvss_score}`}>
                          CVSS {ti.cvss_score}
                        </span>
                      )}
                    </div>
                  )}

                  {/* Explanation (backend-provided only) */}
                  {explanation && (
                    <div className="cc-fc-explanation">
                      <Info size={11} aria-hidden="true" />
                      <span>{explanation}</span>
                    </div>
                  )}

                  {/* Footer CTA */}
                  <div className="cc-fc-footer">
                    <button
                      className="cc-investigate-btn"
                      id={`cc-investigate-${item.finding_id}`}
                      onClick={() => navigate(isScoped && scanRunId && orgId ? `/findings/${item.finding_id}?scan_run_id=${encodeURIComponent(scanRunId)}&org_id=${encodeURIComponent(orgId)}` : `/findings/${item.finding_id}`)}
                      aria-label={`Investigate: ${item.vulnerability_name}`}
                    >
                      Investigate <ArrowRight size={13} aria-hidden="true" />
                    </button>
                  </div>
                </div>
              );
            })}

            {/* Pagination */}
            {filteredFindings.length > PAGE_SIZE && (
              <div className="cc-pagination" role="navigation" aria-label="Findings pagination">
                <span className="cc-pag-info">
                  Showing {(page-1)*PAGE_SIZE+1}–{Math.min(page*PAGE_SIZE, filteredFindings.length)} of {filteredFindings.length} findings
                </span>
                <div className="cc-pag-controls">
                  <button className="cc-page-btn" onClick={() => setPage(p => Math.max(1,p-1))} disabled={page===1} aria-label="Previous page">
                    <ChevronLeft size={14} aria-hidden="true" />
                  </button>
                  {Array.from({length: totalPages}, (_,i) => i+1).map(p => (
                    <button
                      key={p}
                      className={`cc-page-btn ${p===page ? 'cc-page-active' : ''}`}
                      onClick={() => setPage(p)}
                      aria-label={`Page ${p}`}
                      aria-current={p===page ? 'page' : undefined}
                    >{p}</button>
                  ))}
                  <button className="cc-page-btn" onClick={() => setPage(p => Math.min(totalPages,p+1))} disabled={page===totalPages} aria-label="Next page">
                    <ChevronRight size={14} aria-hidden="true" />
                  </button>
                </div>
                <div className="cc-pag-size">
                  Rows per page: <strong>{PAGE_SIZE}</strong>
                </div>
              </div>
            )}
            {filteredFindings.length > 0 && filteredFindings.length <= PAGE_SIZE && (
              <div className="cc-findings-count" aria-live="polite">
                Showing {filteredFindings.length} of {rawFindings.length} finding{rawFindings.length !== 1 ? 's' : ''}
                {hasFilters && (
                  <button className="cc-reset-inline-btn" onClick={resetFilters}>Reset filters</button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT SIDEBAR */}
        <div className="cc-sidebar">

          {rawFindings.length > 0 && (
            <>
              {/* Risk Distribution */}
              <div className="cc-panel" role="region" aria-label="Risk distribution">
                <div className="cc-panel-header">
                  <div className="cc-panel-title">
                    <Shield size={14} style={{ color: '#6366F1' }} aria-hidden="true" />
                    Risk Distribution
                  </div>
                  {totalDonut > 0 && (
                    <span style={{ fontSize: 11, color: '#94A3B8' }}>
                      <Info size={12} aria-hidden="true" />
                    </span>
                  )}
                </div>
                {totalDonut > 0 ? (
                  <div className="cc-donut-wrap">
                    <ResponsiveContainer width="100%" height={140}>
                      <PieChart>
                        <Pie
                          data={donutData.filter(d => d.value > 0)}
                          cx="50%" cy="50%"
                          innerRadius={42} outerRadius={60}
                          paddingAngle={2} dataKey="value" strokeWidth={0}
                        >
                          {donutData.filter(d => d.value > 0).map((e,i) => (
                            <Cell key={i} fill={e.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="cc-donut-legend">
                      {donutData.map(d => (
                        <div key={d.name} className="cc-donut-row">
                          <div className="cc-donut-row-left">
                            <span className="cc-donut-dot" style={{ background: d.color }} aria-hidden="true" />
                            <span>{d.name}</span>
                          </div>
                          <span className="cc-donut-val">
                            {d.value} <span className="cc-donut-pct">({d.pct})</span>
                          </span>
                        </div>
                      ))}
                      <div className="cc-donut-total">Total {totalDonut}</div>
                    </div>
                  </div>
                ) : (
                  <p className="cc-sidebar-empty">No risk data available.</p>
                )}
              </div>

              {/* SLA Overview */}
              <div className="cc-panel" role="region" aria-label="SLA overview">
                <div className="cc-panel-header" style={{ marginBottom: 12 }}>
                  <div className="cc-panel-title">
                    <Clock size={14} style={{ color: '#6366F1' }} aria-hidden="true" />
                    SLA Overview
                  </div>
                  <button
                    className="cc-sla-view-btn"
                    id="cc-sla-open-monitor-btn"
                    onClick={() => navigate(isScoped && scanRunId && orgId ? `/sla?scan_run_id=${encodeURIComponent(scanRunId)}&org_id=${encodeURIComponent(orgId)}` : '/sla')}
                    title="Open full SLA Monitor page"
                  >
                    Open Monitor <ArrowRight size={11} aria-hidden="true" />
                  </button>
                </div>
                <div className="cc-sla-overview-list">
                  {[
                    { key: 'BREACHED', label: 'Breached', dotClass: 'cc-sla-dot-breach', filter: 'BREACHED' },
                    { key: 'AT_RISK',  label: 'At Risk',  dotClass: 'cc-sla-dot-risk',   filter: 'AT_RISK'  },
                    { key: 'HEALTHY',  label: 'Healthy',  dotClass: 'cc-sla-dot-ok',     filter: 'HEALTHY'  },
                  ].map(({ key, label, dotClass, filter }) => (
                    <div
                      key={key}
                      className="cc-sla-ov-row"
                      onClick={() => {
                        setFilterSla(filter);
                        setFilterSev('ALL');
                        setPage(1);
                      }}
                      title={`Click to filter priority findings by ${label}`}
                    >
                      <div className="cc-sla-ov-left">
                        <span className={`cc-sla-dot ${dotClass}`} aria-hidden="true" />
                        <span>{label}</span>
                      </div>
                      <div className="cc-sla-ov-right">
                        <span className="cc-sla-count">{slaOverview[key]} finding{slaOverview[key] !== 1 ? 's' : ''}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Pipeline Health */}
          <PipelineHealth runtimeStatus={runtimeStatus} />
        </div>
      </div>

      {/* NEXT BEST ACTION */}
      {nba && (
        <div className="cc-nba-bar" role="complementary" aria-label="Next best action">
          <div className="cc-nba-left">
            <span className="cc-nba-star" aria-hidden="true">★</span>
            <span className="cc-nba-label">Next Best Action</span>
            <span className="cc-nba-text">{nba.text}</span>
          </div>
          <button
            className="cc-nba-btn"
            id="cc-nba-btn"
            onClick={() => navigate(`/findings/${nba.findingId}`)}
            aria-label={`View finding details: ${nba.text}`}
          >
            View Finding Details <ArrowRight size={13} aria-hidden="true" />
          </button>
        </div>
      )}

    </div>
  );
}
