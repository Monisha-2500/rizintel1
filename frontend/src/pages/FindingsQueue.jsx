import React, { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useFindings } from '../hooks/useFindings';
import FindingsFilters from '../components/findings/FindingsFilters';
import FindingsTable from '../components/findings/FindingsTable';
import { comparePriority } from '../utils/priorityQueue';
import { getRuntimeStatus, RUNTIME_STATUS, getCurrentUser } from '../services/findingsService';
import {
  ShieldAlert, ShieldCheck, Clock, Info,
  ChevronLeft, ChevronRight, RotateCcw,
  AlertCircle, X, Shield, Target, Layers, AlertTriangle, Search,
  GitCommit, ListChecks
} from 'lucide-react';

/**
 * Checks if a finding matches a search query across title, CVE, asset name,
 * asset ID, target host, vulnerability type, scanner names, risk drivers, and explanations.
 */
function matchesFinding(f, query) {
  if (!query || !query.trim()) return true;
  const terms = query.toLowerCase().trim().split(/\s+/);

  const assetName = f.detail?.asset_context?.asset_name || f.asset_name || '';
  const assetId = f.asset_id || '';
  const host = f.detail?.asset_context?.host || f.target_host || f.host || '';
  const scannerNames = (f.detail?.scanner_consensus?.scanner_names || []).join(' ');
  const riskDrivers = (f.detail?.explanation?.top_risk_drivers || []).join(' ');
  const techExplain = f.detail?.explanation?.technical || '';
  const mgmtExplain = f.detail?.explanation?.management || '';
  const recAction = f.recommended_action || '';
  const env = f.detail?.asset_context?.environment || '';
  const dataSensitivity = f.detail?.asset_context?.data_sensitivity || '';
  const exposureText = f.internet_exposure ? 'internet facing internet-facing public' : 'internal network private';
  const kevText = f.detail?.threat_intelligence?.kev_listed ? 'kev cisa known exploited' : '';
  const exploitText = f.detail?.threat_intelligence?.exploit_available ? 'exploit ready available' : '';
  const confidence = f.confidence_classification || '';
  const slaStatus = f.workflow?.sla_status || '';
  const status = f.workflow?.status || '';
  const ticketId = f.workflow?.ticket_id || '';
  const riskLevel = f.risk_level || '';
  const riskScore = String(f.risk_score ?? '');
  const cveId = f.cve_id || '';
  const vulnName = f.vulnerability_name || '';
  const vulnType = f.vulnerability_type || '';
  const findingId = f.finding_id || '';

  const combinedSearchableString = [
    vulnName,
    vulnType,
    cveId,
    findingId,
    assetId,
    assetName,
    host,
    riskLevel,
    riskScore,
    recAction,
    confidence,
    slaStatus,
    status,
    ticketId,
    scannerNames,
    riskDrivers,
    techExplain,
    mgmtExplain,
    env,
    dataSensitivity,
    exposureText,
    kevText,
    exploitText
  ].filter(Boolean).join(' ').toLowerCase();

  return terms.every(term => combinedSearchableString.includes(term));
}

export default function FindingsQueue() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const scanRunId = searchParams.get('scan_run_id');
  const orgId = searchParams.get('org_id');

  const { findings, loading, error } = useFindings(scanRunId, orgId);

  const urlQuery = searchParams.get('q') || searchParams.get('search') || '';
  const [search,          setSearch]          = useState(urlQuery);
  const [debouncedSearch, setDebouncedSearch] = useState(urlQuery);
  const [riskLevel,       setRiskLevel]       = useState('');
  const [confidence,      setConfidence]      = useState('');
  const [criticality,     setCriticality]     = useState('');
  const [exposure,        setExposure]        = useState('');
  const [kev,             setKev]             = useState('');
  const [sla,             setSla]             = useState('');
  const [status,          setStatus]          = useState('');
  const [sorting,         setSorting]         = useState('risk_desc');

  const [currentUser, setCurrentUser] = useState(() => getCurrentUser());
  const [runtimeStatus, setRtStatus] = useState(() => getRuntimeStatus());

  useEffect(() => {
    const handleAuthChange = () => setCurrentUser(getCurrentUser());
    const handleRtChange = () => setRtStatus(getRuntimeStatus());

    window.addEventListener('rizintel-auth-change', handleAuthChange);
    window.addEventListener('rizintel-runtimestatus-change', handleRtChange);
    return () => {
      window.removeEventListener('rizintel-auth-change', handleAuthChange);
      window.removeEventListener('rizintel-runtimestatus-change', handleRtChange);
    };
  }, []);

  // Debounce search query
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
    }, 150);
    return () => clearTimeout(timer);
  }, [search]);

  // Keep search in sync with URL
  useEffect(() => {
    const q = searchParams.get('q') || searchParams.get('search') || '';
    setSearch(q);
    setDebouncedSearch(q);
  }, [searchParams]);

  const handleSearchChange = (newVal) => {
    setSearch(newVal);
    const newParams = new URLSearchParams(searchParams);
    if (newVal.trim()) {
      newParams.set('q', newVal);
    } else {
      newParams.delete('q');
      newParams.delete('search');
    }
    setSearchParams(newParams, { replace: true });
  };

  const handleClearScope = () => {
    const newParams = new URLSearchParams(searchParams);
    newParams.delete('scan_run_id');
    newParams.delete('org_id');
    setSearchParams(newParams);
  };

  const handleRefresh = () => {
    window.dispatchEvent(new CustomEvent('rizintel-datamode-change'));
  };

  // Pagination states
  const [page, setPage]               = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(5);

  // Summary Metrics computed from all authoritative findings
  const summaryKPIs = useMemo(() => {
    if (!findings || findings.length === 0) {
      return { total: 0, critical: 0, high: 0, slaAtRisk: 0, slaBreached: 0, kev: 0, needsReview: 0 };
    }
    const critical = findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'CRITICAL').length;
    const high = findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'HIGH').length;
    const slaAtRisk = findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'AT_RISK').length;
    const slaBreached = findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'BREACHED').length;
    const kevListed = findings.filter(f => f.detail?.threat_intelligence?.kev_listed === true).length;
    const needsReview = findings.filter(f => (f.confidence_classification ?? '').toUpperCase() === 'NEEDS_REVIEW').length;
    const total = findings.length;

    return { total, critical, high, slaAtRisk, slaBreached, kev: kevListed, needsReview };
  }, [findings]);

  // Filter and Sort Findings
  const filteredFindings = useMemo(() => {
    if (!findings) return [];

    let result = [...findings];

    if (debouncedSearch.trim()) {
      result = result.filter(f => matchesFinding(f, debouncedSearch));
    }

    if (riskLevel)   result = result.filter(f => (f.risk_level ?? '').toUpperCase() === riskLevel);
    if (confidence)  result = result.filter(f => (f.confidence_classification ?? '').toUpperCase() === confidence);
    if (criticality) result = result.filter(f => (f.asset_criticality ?? '').toUpperCase() === criticality);
    if (exposure)    result = result.filter(f => f.internet_exposure === (exposure === 'true'));
    if (kev)         result = result.filter(f => (f.detail?.threat_intelligence?.kev_listed ?? false) === (kev === 'true'));
    if (sla)         result = result.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === sla);
    if (status)      result = result.filter(f => (f.workflow?.status ?? '').toUpperCase() === status);

    result.sort((a, b) => {
      if (sorting === 'risk_desc') return comparePriority(a, b);
      if (sorting === 'score_desc') return (b.risk_score ?? 0) - (a.risk_score ?? 0);
      if (sorting === 'score_asc')  return (a.risk_score ?? 0) - (b.risk_score ?? 0);
      if (sorting === 'epss_desc') {
        return (b.detail?.threat_intelligence?.epss_score ?? 0) - (a.detail?.threat_intelligence?.epss_score ?? 0);
      }
      if (sorting === 'cvss_desc') {
        return (b.detail?.threat_intelligence?.cvss_score ?? 0) - (a.detail?.threat_intelligence?.cvss_score ?? 0);
      }
      if (sorting === 'confidence_desc') {
        return (b.detail?.finding_confidence?.score ?? 0) - (a.detail?.finding_confidence?.score ?? 0);
      }
      if (sorting === 'sla_urgency') {
        const order = { BREACHED: 4, AT_RISK: 3, PENDING_REVIEW: 2, ON_TRACK: 1, MET: 0 };
        return (order[(b.workflow?.sla_status ?? '').toUpperCase()] ?? 0) - (order[(a.workflow?.sla_status ?? '').toUpperCase()] ?? 0);
      }
      return 0;
    });

    return result;
  }, [findings, debouncedSearch, riskLevel, confidence, criticality, exposure, kev, sla, status, sorting]);

  // Paginated findings slice
  const totalPages = Math.ceil(filteredFindings.length / rowsPerPage) || 1;
  const startIndex = (page - 1) * rowsPerPage;
  const paginatedFindings = filteredFindings.slice(startIndex, startIndex + rowsPerPage);

  // Reset to page 1 when filter parameters change
  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, riskLevel, confidence, criticality, exposure, kev, sla, status, sorting, rowsPerPage]);

  const resetFilters = () => {
    setSearch('');
    setRiskLevel('');
    setConfidence('');
    setCriticality('');
    setExposure('');
    setKev('');
    setSla('');
    setStatus('');
    setSorting('risk_desc');
  };

  // ── 1. LOADING SKELETON STATE ─────────────────────────────────────────────
  if (loading) {
    return (
      <div className="findings-queue-container" aria-busy="true" aria-label="Loading findings">
        <div className="findings-header-block skeleton-header">
          <div className="findings-header-left">
            <div className="skeleton-title" />
            <div className="skeleton-sub" />
          </div>
          <div className="findings-summary-cards-row">
            {[1, 2, 3, 4, 5].map(k => (
              <div key={k} className="f-summary-card skeleton-card" />
            ))}
          </div>
        </div>

        <div className="findings-cards-list">
          {[1, 2, 3, 4].map(idx => (
            <div key={idx} className="finding-card-row skeleton-finding-row">
              <div className="skeleton-box rank" />
              <div className="skeleton-box score" />
              <div className="skeleton-body" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  // ── 2. ERROR STATE (ZERO MOCK FALLBACK) ───────────────────────────────────
  if (error) {
    return (
      <div className="findings-queue-container">
        <div className="findings-error-state" role="alert">
          <div className="error-state-icon">
            <AlertCircle size={40} />
          </div>
          <h2>Unable to load findings</h2>
          <p>RizIntel couldn't retrieve findings right now: {error}</p>
          <button
            className="findings-retry-btn"
            onClick={() => window.location.reload()}
            id="btn-retry-findings"
          >
            <RotateCcw size={15} />
            <span>Retry</span>
          </button>
        </div>
      </div>
    );
  }

  // ── 3. ZERO FINDINGS GLOBAL EMPTY STATE ────────────────────────────────────
  if (!findings || findings.length === 0) {
    return (
      <div className="findings-queue-container">
        {/* Scoped Banner if present */}
        {scanRunId && (
          <div className="findings-scope-banner">
            <span className="scope-icon">🎯</span>
            <span className="scope-text">
              Viewing findings for Scan Run <strong>{scanRunId}</strong>
            </span>
            <button className="scope-clear-btn" onClick={handleClearScope}>
              Clear Filter
            </button>
          </div>
        )}

        <div className="findings-global-empty-state">
          <div className="empty-icon-shield">
            <Shield size={48} />
          </div>
          <h2>No findings yet</h2>
          <p>Completed security scans will appear here after analysis.</p>
          {currentUser?.role !== 'VIEWER' ? (
            <button
              className="findings-primary-cta-btn"
              onClick={() => navigate('/scan-runs')}
              id="btn-create-scan-run"
            >
              Create Scan Run
            </button>
          ) : (
            <span className="viewer-hint-text">
              You have read-only access. Scan runs scheduled by administrators will appear here.
            </span>
          )}
        </div>
      </div>
    );
  }

  // ── 4. NORMAL FINDINGS QUEUE VIEW ─────────────────────────────────────────
  return (
    <div className="findings-queue-container">
      {/* ═════════════════════════════════════════════════════════════════════
          HEADER: Eyebrow + Title + Subtitle + Top-Right RizTrace Action
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="cc-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, color: '#6366F1', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
            <ListChecks size={14} />
            <span>Findings & Urgency Queue</span>
            {orgId && <><span style={{ opacity: 0.4, margin: '0 4px' }}>/</span><span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: 11, color: '#64748B' }}>{orgId}</span></>}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 className="cc-title" style={{ margin: 0 }}>Findings</h1>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 12, fontSize: 11.5, fontWeight: 600, background: '#ECFDF5', color: '#059669', border: '1px solid #A7F3D0' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10B981' }} />
              Active Queue
            </span>
          </div>
          <p className="cc-subtitle" style={{ margin: '4px 0 0 0' }}>
            Prioritize security risk, monitor remediation urgency, and investigate the findings that matter most.
          </p>
        </div>

        <div className="cc-header-actions" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={() => {
              const targetId = filteredFindings[0]?.finding_id || 'DEDUP-0001';
              navigate(`/findings/${encodeURIComponent(targetId)}/riztrace${scanRunId ? `?scan_run_id=${scanRunId}` : ''}`);
            }}
            className="riztrace-header-btn"
            id="btn-riztrace-header"
            aria-label="Open RizTrace Provenance View"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              padding: '9px 18px',
              borderRadius: 10,
              border: '1px solid #818CF8',
              background: 'linear-gradient(135deg, #6366F1 0%, #4F46E5 100%)',
              color: '#FFFFFF',
              fontSize: 13.5,
              fontWeight: 600,
              boxShadow: '0 4px 14px rgba(99, 102, 241, 0.3)',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
          >
            <GitCommit size={16} />
            <span>RizTrace</span>
          </button>
        </div>
      </div>

      {/* Scoped Banner if present */}
      {scanRunId && (
        <div className="cc-scope-banner" role="status" style={{ marginBottom: 12 }}>
          <div className="cc-scope-info">
            <span className="scope-icon" aria-hidden="true">🎯</span>
            <span>Viewing findings for Scan Run <strong>{scanRunId}</strong></span>
          </div>
          <button
            className="cc-scope-clear-btn"
            onClick={handleClearScope}
            id="btn-clear-scan-scope"
            aria-label="Clear scan run filter"
          >
            Clear Filter <X size={12} aria-hidden="true" />
          </button>
        </div>
      )}

      {/* ═════════════════════════════════════════════════════════════════════
          5 SUMMARY KPI METRIC CARDS (Exact match to CommandCenter)
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="cc-summary-row" role="region" aria-label="Findings summary metrics">
        <div
          className={`cc-summary-card cc-sum-critical${riskLevel === 'CRITICAL' ? ' active' : ''}`}
          onClick={() => setRiskLevel(riskLevel === 'CRITICAL' ? '' : 'CRITICAL')}
          style={{ cursor: 'pointer' }}
          role="button"
          tabIndex={0}
          title="Filter by Critical risk findings"
        >
          <div className="cc-sum-icon"><ShieldAlert size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${summaryKPIs.critical} critical findings`}>{summaryKPIs.critical}</div>
          <div className="cc-sum-label">Critical Risk</div>
          <div className="cc-sum-sub">Active critical findings</div>
        </div>

        <div
          className={`cc-summary-card cc-sum-high${riskLevel === 'HIGH' ? ' active' : ''}`}
          onClick={() => setRiskLevel(riskLevel === 'HIGH' ? '' : 'HIGH')}
          style={{ cursor: 'pointer' }}
          role="button"
          tabIndex={0}
          title="Filter by High risk findings"
        >
          <div className="cc-sum-icon"><AlertTriangle size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${summaryKPIs.high} high findings`}>{summaryKPIs.high}</div>
          <div className="cc-sum-label">High Risk</div>
          <div className="cc-sum-sub">Active high findings</div>
        </div>

        <div
          className={`cc-summary-card cc-sum-sla-risk${sla === 'AT_RISK' ? ' active' : ''}`}
          onClick={() => setSla(sla === 'AT_RISK' ? '' : 'AT_RISK')}
          style={{ cursor: 'pointer' }}
          role="button"
          tabIndex={0}
          title="Filter by SLA At Risk findings"
        >
          <div className="cc-sum-icon"><Clock size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${summaryKPIs.slaAtRisk} findings at SLA risk`}>{summaryKPIs.slaAtRisk}</div>
          <div className="cc-sum-label">SLA At Risk</div>
          <div className="cc-sum-sub">Due within 24 hours</div>
        </div>

        <div
          className={`cc-summary-card cc-sum-sla-breach${sla === 'BREACHED' ? ' active' : ''}`}
          onClick={() => setSla(sla === 'BREACHED' ? '' : 'BREACHED')}
          style={{ cursor: 'pointer' }}
          role="button"
          tabIndex={0}
          title="Filter by SLA Breached findings"
        >
          <div className="cc-sum-icon"><AlertCircle size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${summaryKPIs.slaBreached} findings breached SLA`}>{summaryKPIs.slaBreached}</div>
          <div className="cc-sum-label">SLA Breached</div>
          <div className="cc-sum-sub">Past due</div>
        </div>

        <div
          className={`cc-summary-card cc-sum-active${!riskLevel && !kev && !sla && !confidence && !status ? ' active' : ''}`}
          onClick={resetFilters}
          style={{ cursor: 'pointer' }}
          role="button"
          tabIndex={0}
          title="Show all active findings"
        >
          <div className="cc-sum-icon"><Layers size={18} aria-hidden="true" /></div>
          <div className="cc-sum-num" aria-label={`${summaryKPIs.total} active findings`}>{summaryKPIs.total}</div>
          <div className="cc-sum-label">Active Findings</div>
          <div className="cc-sum-sub">All open findings</div>
        </div>
      </div>

      {/* ═════════════════════════════════════════════════════════════════════
          MAIN FINDINGS PANEL: Priority Attention Panel with Filter Bar
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="cc-panel" style={{ marginTop: 6 }}>
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

        {/* Filter bar (Exact parity with CommandCenter cc-filter-bar) */}
        <FindingsFilters
          search={search} setSearch={handleSearchChange}
          riskLevel={riskLevel} setRiskLevel={setRiskLevel}
          confidence={confidence} setConfidence={setConfidence}
          sla={sla} setSla={setSla}
          status={status} setStatus={setStatus}
          sorting={sorting} setSorting={setSorting}
          onRefresh={handleRefresh}
        />

        {/* Findings List or Filter-Empty State */}
        {filteredFindings.length === 0 ? (
          <div className="cc-empty-filtered" role="status">
            <Search size={32} color="#94A3B8" aria-hidden="true" />
            <p>No findings match your filters.</p>
            <button
              className="cc-reset-filters-btn"
              onClick={resetFilters}
              id="btn-reset-filters-no-match"
            >
              Reset Filters
            </button>
          </div>
        ) : (
          <FindingsTable
            findings={paginatedFindings}
            startIndex={startIndex}
          />
        )}

        {/* Pagination Footer */}
        {filteredFindings.length > 0 && (
          <div className="findings-pagination-footer" role="navigation" aria-label="Pagination">
            <div className="pagination-info-text">
              Showing {startIndex + 1} to {Math.min(startIndex + rowsPerPage, filteredFindings.length)} of {filteredFindings.length} findings
            </div>

            <div className="pagination-controls-group">
              <button
                className="pagination-nav-btn"
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                title="Previous page"
                aria-label="Previous page"
              >
                <ChevronLeft size={16} />
              </button>

              {Array.from({ length: totalPages }, (_, idx) => {
                const pNum = idx + 1;
                return (
                  <button
                    key={pNum}
                    className={`pagination-number-btn${page === pNum ? ' active' : ''}`}
                    onClick={() => setPage(pNum)}
                    aria-label={`Page ${pNum}`}
                    aria-current={page === pNum ? 'page' : undefined}
                  >
                    {pNum}
                  </button>
                );
              })}

              <button
                className="pagination-nav-btn"
                disabled={page >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                title="Next page"
                aria-label="Next page"
              >
                <ChevronRight size={16} />
              </button>
            </div>

            <div className="pagination-rows-selector">
              <span className="rows-label">Rows per page:</span>
              <div className="rows-dropdown-wrapper">
                <select
                  value={rowsPerPage}
                  onChange={e => {
                    setRowsPerPage(Number(e.target.value));
                    setPage(1);
                  }}
                  className="rows-select-field"
                  aria-label="Rows per page"
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
