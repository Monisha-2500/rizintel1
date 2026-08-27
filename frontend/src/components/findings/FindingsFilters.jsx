import React from 'react';
import { Search, X, RefreshCw } from 'lucide-react';

export default function FindingsFilters({
  search, setSearch,
  riskLevel, setRiskLevel,
  confidence, setConfidence,
  sla, setSla,
  status, setStatus,
  sorting, setSorting,
  onRefresh,
}) {
  return (
    <div className="cc-filter-bar" role="search" aria-label="Filter findings queue">
      {/* Search Input */}
      <div className="cc-search-wrap">
        <Search size={14} className="cc-search-icon" aria-hidden="true" />
        <input
          id="findings-search-input"
          className="cc-search-input"
          type="text"
          placeholder="Search by finding, CVE, asset or host…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          aria-label="Search findings"
        />
        {search && (
          <button
            className="cc-search-clear"
            onClick={() => setSearch('')}
            aria-label="Clear search"
          >
            <X size={12} aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Severity Select */}
      <label htmlFor="filter-risk-level" className="cc-sr-only">Severity</label>
      <select
        id="filter-risk-level"
        className="cc-filter-select"
        value={riskLevel}
        onChange={e => setRiskLevel(e.target.value)}
        aria-label="Filter by severity"
      >
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>

      {/* SLA Status Select */}
      <label htmlFor="filter-sla-status" className="cc-sr-only">SLA Status</label>
      <select
        id="filter-sla-status"
        className="cc-filter-select"
        value={sla}
        onChange={e => setSla(e.target.value)}
        aria-label="Filter by SLA status"
      >
        <option value="">All SLA States</option>
        <option value="ON_TRACK">Healthy / On Track</option>
        <option value="AT_RISK">At Risk</option>
        <option value="BREACHED">Breached</option>
        <option value="PENDING_REVIEW">Pending Review</option>
      </select>

      {/* Confidence Select */}
      <label htmlFor="filter-confidence" className="cc-sr-only">Confidence</label>
      <select
        id="filter-confidence"
        className="cc-filter-select"
        value={confidence}
        onChange={e => setConfidence(e.target.value)}
        aria-label="Filter by confidence"
      >
        <option value="">All Confidence</option>
        <option value="HIGH_CONFIDENCE">High Confidence</option>
        <option value="CONFIRMED">Confirmed</option>
        <option value="NEEDS_REVIEW">Needs Review</option>
        <option value="LIKELY_NOISE">Likely Noise</option>
      </select>

      {/* Workflow Status Select */}
      <label htmlFor="filter-status" className="cc-sr-only">Status</label>
      <select
        id="filter-status"
        className="cc-filter-select"
        value={status}
        onChange={e => setStatus(e.target.value)}
        aria-label="Filter by status"
      >
        <option value="">All Statuses</option>
        <option value="OPEN">Open</option>
        <option value="IN_PROGRESS">In Progress</option>
        <option value="PENDING_REVIEW">Pending Review</option>
        <option value="RESOLVED">Resolved</option>
      </select>

      {/* Sort Select */}
      <label htmlFor="filter-sorting" className="cc-sr-only">Sort by</label>
      <select
        id="filter-sorting"
        className="cc-filter-select"
        value={sorting}
        onChange={e => setSorting(e.target.value)}
        aria-label="Sort findings"
      >
        <option value="risk_desc">Sort: Highest Risk</option>
        <option value="risk_asc">Sort: Lowest Risk</option>
        <option value="sla_urgency">Sort: SLA Urgency</option>
        <option value="confidence_desc">Sort: Confidence</option>
        <option value="newest">Sort: Newest First</option>
      </select>

      {/* Refresh Button */}
      <button
        id="findings-refresh-btn"
        className="cc-refresh-btn"
        onClick={onRefresh}
        aria-label="Refresh findings"
      >
        <RefreshCw size={14} aria-hidden="true" /> Refresh
      </button>
    </div>
  );
}
