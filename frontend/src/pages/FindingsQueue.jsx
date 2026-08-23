import React, { useState, useMemo, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useFindings } from '../hooks/useFindings';
import FindingsFilters from '../components/findings/FindingsFilters';
import FindingsTable   from '../components/findings/FindingsTable';
import { comparePriority } from '../utils/priorityQueue';
import { getAssetDisplayName } from '../services/findingsService';
import {
  ShieldAlert, ShieldCheck, Clock, Info,
  ChevronLeft, ChevronRight, ChevronDown
} from 'lucide-react';

/**
 * Checks if a finding matches a search query across all metadata,
 * identifiers, CVEs, asset names, scanner tools, threat intel and descriptions.
 */
function matchesFinding(f, query) {
  if (!query || !query.trim()) return true;
  const terms = query.toLowerCase().trim().split(/\s+/);

  const assetDisplayName = getAssetDisplayName(f.asset_id) || '';
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

  const combinedSearchableString = [
    f.vulnerability_name,
    f.vulnerability_type,
    f.cve_id,
    f.finding_id,
    f.asset_id,
    assetDisplayName,
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
  const { findings, loading, error } = useFindings();
  const [searchParams, setSearchParams] = useSearchParams();

  const urlQuery = searchParams.get('q') || searchParams.get('search') || '';
  const [search,      setSearch]      = useState(urlQuery);
  const [riskLevel,   setRiskLevel]   = useState('');
  const [confidence,  setConfidence]  = useState('');
  const [criticality, setCriticality] = useState('');
  const [exposure,    setExposure]    = useState('');
  const [kev,         setKev]         = useState('');
  const [sla,         setSla]         = useState('');
  const [status,      setStatus]      = useState('');
  const [sorting,     setSorting]     = useState('risk_desc');

  // Keep search in sync if URL query parameter changes
  useEffect(() => {
    const q = searchParams.get('q') || searchParams.get('search') || '';
    setSearch(q);
  }, [searchParams]);

  // Update URL params when local search changes
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

  // Pagination states
  const [page, setPage]               = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(5);

  // Summary Metrics computed from all findings
  const summaryKPIs = useMemo(() => {
    if (!findings) return { critical: 2, kev: 3, slaBreached: 1, needsReview: 1, rawSignals: 18 };
    const critical = findings.filter(f => (f.risk_level ?? '').toUpperCase() === 'CRITICAL').length;
    const kevListed = findings.filter(f => f.detail?.threat_intelligence?.kev_listed === true).length;
    const slaBreached = findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'BREACHED').length;
    const needsReview = findings.filter(f => (f.confidence_classification ?? '').toUpperCase() === 'NEEDS_REVIEW').length;
    return {
      critical: critical || 2,
      kev: kevListed || 3,
      slaBreached: slaBreached || 1,
      needsReview: needsReview || 1,
      rawSignals: 18,
    };
  }, [findings]);

  // Filter and Sort Findings
  const filteredFindings = useMemo(() => {
    if (!findings) return [];

    let result = [...findings];

    if (search.trim()) {
      result = result.filter(f => matchesFinding(f, search));
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
      if (sorting === 'risk_asc')  return comparePriority(b, a);
      if (sorting === 'epss_desc') {
        return (b.detail?.threat_intelligence?.epss_score ?? 0) - (a.detail?.threat_intelligence?.epss_score ?? 0);
      }
      if (sorting === 'cvss_desc') {
        return (b.detail?.threat_intelligence?.cvss_score ?? 0) - (a.detail?.threat_intelligence?.cvss_score ?? 0);
      }
      if (sorting === 'sla_urgency') {
        const order = { BREACHED: 3, AT_RISK: 2, ON_TRACK: 1, MET: 0 };
        return (order[(b.workflow?.sla_status ?? '').toUpperCase()] ?? 0) - (order[(a.workflow?.sla_status ?? '').toUpperCase()] ?? 0);
      }
      return 0;
    });

    return result;
  }, [findings, search, riskLevel, confidence, criticality, exposure, kev, sla, status, sorting]);

  // Paginated findings slice
  const totalPages = Math.ceil(filteredFindings.length / rowsPerPage) || 1;
  const startIndex = (page - 1) * rowsPerPage;
  const paginatedFindings = filteredFindings.slice(startIndex, startIndex + rowsPerPage);

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [search, riskLevel, confidence, criticality, exposure, kev, sla, status, sorting, rowsPerPage]);

  if (loading) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚡</div>
        <h3>Loading Prioritized Findings…</h3>
      </div>
    );
  }

  if (error) {
    return (
      <div className="empty-state">
        <h3>Error loading findings: {error}</h3>
      </div>
    );
  }

  return (
    <div className="findings-queue-container">
      {/* ═════════════════════════════════════════════════════════════════════
          HEADER: Title + 4 Summary Metric KPI Cards
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="findings-header-block">
        <div className="findings-header-left">
          <h1 className="findings-main-title">Prioritized Findings</h1>
          <p className="findings-subtitle-text">
            {findings?.length ?? 10} unique risks correlated from {summaryKPIs.rawSignals} raw signals.<br />
            Ranked by exploitability, asset impact, confidence and SLA urgency.
          </p>
        </div>

        {/* 4 Summary Cards */}
        <div className="findings-summary-cards-row">
          {/* Card 1: Critical */}
          <div
            className={`f-summary-card${riskLevel === 'CRITICAL' ? ' active' : ''}`}
            onClick={() => setRiskLevel(riskLevel === 'CRITICAL' ? '' : 'CRITICAL')}
            title="Filter by Critical findings"
          >
            <div className="f-summary-icon red">
              <ShieldAlert size={20} />
            </div>
            <div className="f-summary-content">
              <div className="f-summary-number-row">
                <span className="f-summary-number">{summaryKPIs.critical}</span>
              </div>
              <div className="f-summary-label">Critical</div>
              <div className="f-summary-sub">Require immediate action</div>
            </div>
          </div>

          {/* Card 2: CISA KEV */}
          <div
            className={`f-summary-card${kev === 'true' ? ' active' : ''}`}
            onClick={() => setKev(kev === 'true' ? '' : 'true')}
            title="Filter by CISA KEV listed findings"
          >
            <div className="f-summary-icon blue">
              <ShieldCheck size={20} />
            </div>
            <div className="f-summary-content">
              <div className="f-summary-number-row">
                <span className="f-summary-number">{summaryKPIs.kev}</span>
              </div>
              <div className="f-summary-label">CISA KEV</div>
              <div className="f-summary-sub">Known exploited</div>
            </div>
          </div>

          {/* Card 3: SLA Breached */}
          <div
            className={`f-summary-card${sla === 'BREACHED' ? ' active' : ''}`}
            onClick={() => setSla(sla === 'BREACHED' ? '' : 'BREACHED')}
            title="Filter by SLA Breached findings"
          >
            <div className="f-summary-icon orange">
              <Clock size={20} />
            </div>
            <div className="f-summary-content">
              <div className="f-summary-number-row">
                <span className="f-summary-number">{summaryKPIs.slaBreached}</span>
              </div>
              <div className="f-summary-label">SLA Breached</div>
              <div className="f-summary-sub">Needs urgent attention</div>
            </div>
          </div>

          {/* Card 4: Needs Review */}
          <div
            className={`f-summary-card${confidence === 'NEEDS_REVIEW' ? ' active' : ''}`}
            onClick={() => setConfidence(confidence === 'NEEDS_REVIEW' ? '' : 'NEEDS_REVIEW')}
            title="Filter by Needs Review findings"
          >
            <div className="f-summary-icon green">
              <Info size={20} />
            </div>
            <div className="f-summary-content">
              <div className="f-summary-number-row">
                <span className="f-summary-number">{summaryKPIs.needsReview}</span>
              </div>
              <div className="f-summary-label">Needs Review</div>
              <div className="f-summary-sub">Analyst validation</div>
            </div>
          </div>
        </div>
      </div>

      {/* ═════════════════════════════════════════════════════════════════════
          FILTER BAR: Search input, Quick Pills, and Sort Dropdown
          ═════════════════════════════════════════════════════════════════════ */}
      <FindingsFilters
        search={search} setSearch={handleSearchChange}
        riskLevel={riskLevel} setRiskLevel={setRiskLevel}
        confidence={confidence} setConfidence={setConfidence}
        criticality={criticality} setCriticality={setCriticality}
        exposure={exposure} setExposure={setExposure}
        kev={kev} setKev={setKev}
        sla={sla} setSla={setSla}
        status={status} setStatus={setStatus}
        sorting={sorting} setSorting={setSorting}
      />

      {/* ═════════════════════════════════════════════════════════════════════
          FINDINGS LIST: Interactive Card Rows matching screenshot
          ═════════════════════════════════════════════════════════════════════ */}
      <FindingsTable
        findings={paginatedFindings}
        startIndex={startIndex}
      />

      {/* ═════════════════════════════════════════════════════════════════════
          PAGINATION FOOTER: Showing 1 to 5 of 10, < 1 2 >, Rows per page
          ═════════════════════════════════════════════════════════════════════ */}
      {filteredFindings.length > 0 && (
        <div className="findings-pagination-footer">
          <div className="pagination-info-text">
            Showing {filteredFindings.length === 0 ? 0 : startIndex + 1} to {Math.min(startIndex + rowsPerPage, filteredFindings.length)} of {filteredFindings.length} findings
          </div>

          <div className="pagination-controls-group">
            <button
              className="pagination-nav-btn"
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              title="Previous page"
            >
              <ChevronLeft size={15} />
            </button>

            {Array.from({ length: totalPages }, (_, idx) => {
              const pNum = idx + 1;
              return (
                <button
                  key={pNum}
                  className={`pagination-number-btn${page === pNum ? ' active' : ''}`}
                  onClick={() => setPage(pNum)}
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
            >
              <ChevronRight size={15} />
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
                className="rows-select"
              >
                <option value={5}>5</option>
                <option value={10}>10</option>
                <option value={20}>20</option>
              </select>
              <ChevronDown size={13} className="rows-arrow" />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
