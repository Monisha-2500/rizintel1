import React, { useState, useRef, useEffect } from 'react';
import { Search, Flame, Globe, Clock, Plus, X, RotateCcw, ChevronDown, Check } from 'lucide-react';

export default function FindingsFilters({
  search, setSearch,
  riskLevel, setRiskLevel,
  confidence, setConfidence,
  criticality, setCriticality,
  exposure, setExposure,
  kev, setKev,
  sla, setSla,
  status, setStatus,
  sorting, setSorting,
}) {
  const [showMoreModal, setShowMoreModal] = useState(false);
  const modalRef = useRef(null);

  // Close dropdown when clicked outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (modalRef.current && !modalRef.current.contains(event.target)) {
        setShowMoreModal(false);
      }
    }
    if (showMoreModal) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showMoreModal]);

  const hasMoreFiltersActive = confidence || criticality || status;

  const resetAll = () => {
    setSearch('');
    setRiskLevel('');
    setConfidence('');
    setCriticality('');
    setExposure('');
    setKev('');
    setSla('');
    setStatus('');
    setSorting('risk_desc');
    setShowMoreModal(false);
  };

  return (
    <div className="findings-filter-bar-container">
      <div className="findings-filter-bar">
        {/* Search Input */}
        <div className="findings-search-wrapper">
          <Search size={15} className="findings-search-icon" />
          <input
            type="text"
            placeholder="Search vulnerabilities, CVEs, assets..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="findings-search-input-field"
            id="findings-search-input"
          />
          {search && (
            <button className="search-clear-btn" onClick={() => setSearch('')} title="Clear search">
              <X size={13} />
            </button>
          )}
        </div>

        {/* Quick Filter Pills matching Screenshot */}
        <div className="findings-pills-group">
          {/* Critical Pill */}
          <button
            id="filter-pill-critical"
            className={`f-pill red${riskLevel === 'CRITICAL' ? ' active' : ''}`}
            onClick={() => setRiskLevel(riskLevel === 'CRITICAL' ? '' : 'CRITICAL')}
          >
            <Flame size={13} />
            <span>Critical</span>
          </button>

          {/* CISA KEV Pill */}
          <button
            id="filter-pill-kev"
            className={`f-pill red${kev === 'true' ? ' active' : ''}`}
            onClick={() => setKev(kev === 'true' ? '' : 'true')}
          >
            <Flame size={13} />
            <span>CISA KEV</span>
          </button>

          {/* Internet-facing Pill */}
          <button
            id="filter-pill-exposure"
            className={`f-pill blue${exposure === 'true' ? ' active' : ''}`}
            onClick={() => setExposure(exposure === 'true' ? '' : 'true')}
          >
            <Globe size={13} />
            <span>Internet-facing</span>
          </button>

          {/* SLA Urgency Pill */}
          <button
            id="filter-pill-sla"
            className={`f-pill orange${sla === 'BREACHED' || sla === 'AT_RISK' ? ' active' : ''}`}
            onClick={() => setSla(sla ? '' : 'AT_RISK')}
          >
            <Clock size={13} />
            <span>SLA Urgency</span>
          </button>

          {/* More Filters Pill with Popover */}
          <div className="more-filters-anchor" ref={modalRef}>
            <button
              id="filter-pill-more"
              className={`f-pill purple${hasMoreFiltersActive ? ' active' : ''}`}
              onClick={() => setShowMoreModal(prev => !prev)}
            >
              <Plus size={13} />
              <span>More Filters</span>
              {hasMoreFiltersActive && <span className="pill-dot" />}
            </button>

            {showMoreModal && (
              <div className="more-filters-popover">
                <div className="popover-header">
                  <span className="popover-title">Additional Filters</span>
                  <button className="popover-close-btn" onClick={() => setShowMoreModal(false)}>
                    <X size={14} />
                  </button>
                </div>

                <div className="popover-body">
                  <div className="popover-field">
                    <label>Confidence Level</label>
                    <select
                      value={confidence}
                      onChange={e => setConfidence(e.target.value)}
                      className="popover-select"
                    >
                      <option value="">All Confidence Levels</option>
                      <option value="CONFIRMED">Confirmed</option>
                      <option value="HIGH_CONFIDENCE">High Confidence</option>
                      <option value="NEEDS_REVIEW">Needs Review</option>
                      <option value="LIKELY_NOISE">Likely Noise</option>
                    </select>
                  </div>

                  <div className="popover-field">
                    <label>Asset Criticality</label>
                    <select
                      value={criticality}
                      onChange={e => setCriticality(e.target.value)}
                      className="popover-select"
                    >
                      <option value="">All Criticalities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>

                  <div className="popover-field">
                    <label>Workflow Status</label>
                    <select
                      value={status}
                      onChange={e => setStatus(e.target.value)}
                      className="popover-select"
                    >
                      <option value="">All Statuses</option>
                      <option value="OPEN">Open</option>
                      <option value="IN_PROGRESS">In Progress</option>
                      <option value="RESOLVED">Resolved</option>
                    </select>
                  </div>
                </div>

                <div className="popover-footer">
                  <button className="popover-reset-btn" onClick={resetAll}>
                    <RotateCcw size={12} /> Reset All
                  </button>
                  <button className="popover-apply-btn" onClick={() => setShowMoreModal(false)}>
                    Apply Filters
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Sort By Dropdown */}
        <div className="findings-sort-container">
          <span className="findings-sort-label">Sort by:</span>
          <div className="sort-select-wrapper">
            <select
              className="findings-sort-dropdown"
              value={sorting}
              onChange={e => setSorting(e.target.value)}
              id="findings-sort-select"
            >
              <option value="risk_desc">Priority</option>
              <option value="risk_asc">Lowest Risk</option>
              <option value="epss_desc">EPSS Score</option>
              <option value="cvss_desc">CVSS Score</option>
              <option value="sla_urgency">SLA Urgency</option>
            </select>
            <ChevronDown size={14} className="sort-select-arrow" />
          </div>
        </div>
      </div>
    </div>
  );
}
