import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Shield, AlertTriangle, ArrowRight, CheckCircle2,
  Clock, Flame, Globe, Lightbulb
} from 'lucide-react';
import {
  formatConfidence,
  formatSla,
  formatAssetDisplay,
  formatCve,
  cleanCustomerText,
  getWhyItMatters
} from '../../utils/customerFacingText';

function getStripeColor(riskScore, rank, riskLevel) {
  const level = (riskLevel || '').toUpperCase();
  if (level === 'CRITICAL' || riskScore >= 90 || rank === 1) return '#DC2626';
  if (level === 'HIGH' || riskScore >= 70) return '#EA580C';
  if (level === 'MEDIUM' || riskScore >= 40) return '#F59E0B';
  return '#10B981';
}

export default function FindingsTable({ findings, startIndex = 0 }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const handleInvestigate = (findingId, e) => {
    e.stopPropagation();
    const params = new URLSearchParams();
    const scanRunId = searchParams.get('scan_run_id');
    const orgId = searchParams.get('org_id');
    if (scanRunId) params.set('scan_run_id', scanRunId);
    if (orgId) params.set('organization_id', orgId);

    const queryString = params.toString() ? `?${params.toString()}` : '';
    navigate(`/findings/${findingId}${queryString}`);
  };

  return (
    <div className="findings-cards-list" role="feed" aria-label="Prioritized Findings List">
      {findings.map((f, index) => {
        const rank = startIndex + index + 1;
        const score = f.risk_score != null ? Math.round(f.risk_score) : 0;
        const level = (f.risk_level || 'LOW').toUpperCase();

        const epss = f.detail?.threat_intelligence?.epss_score;
        const isKev = f.detail?.threat_intelligence?.kev_listed === true;
        const isInternet = f.internet_exposure === true;
        const scannerCount = f.detail?.scanner_consensus?.detected_by_count ?? 1;
        const totalScanners = f.detail?.scanner_consensus?.total_scanners ?? 3;

        const stripeColor = getStripeColor(score, rank, level);
        const { primaryName, secondaryId } = formatAssetDisplay(f);
        const cveInfo = formatCve(f.cve_id);
        const confInfo = formatConfidence(f);
        const slaInfo = formatSla(f);
        const whyMattersText = getWhyItMatters(f);

        const findingTitle = cleanCustomerText(f.vulnerability_name || 'Unspecified Vulnerability');

        return (
          <article
            key={f.finding_id}
            className="finding-card-row"
            style={{ borderLeftColor: stripeColor }}
            onClick={(e) => handleInvestigate(f.finding_id, e)}
            tabIndex={0}
            role="article"
            aria-labelledby={`finding-title-${f.finding_id}`}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleInvestigate(f.finding_id, e);
              }
            }}
          >
            {/* 1. Rank Box */}
            <div className="finding-rank-box" title={`Priority Rank #${rank}`} aria-label={`Priority Rank ${rank}`}>
              {rank}
            </div>

            {/* 2. Risk Score Box */}
            <div
              className={`finding-score-box ${level.toLowerCase()}`}
              aria-label={`Risk score ${score}, ${level} severity`}
            >
              <div className="finding-score-num">{score}</div>
              <div className="finding-score-level">{level}</div>
            </div>

            {/* 3. Vulnerability Info & Telemetry Badges */}
            <div className="finding-info-col">
              <div className="finding-title-row">
                <h3
                  className="finding-vuln-name"
                  id={`finding-title-${f.finding_id}`}
                  title={findingTitle}
                  tabIndex={0}
                  aria-label={`Vulnerability: ${findingTitle}`}
                >
                  {findingTitle}
                </h3>
              </div>

              {/* Asset and CVE context lines */}
              <div className="finding-meta-row">
                <span className={`finding-cve-pill ${cveInfo.isAssigned ? 'assigned' : 'unassigned'}`}>
                  {cveInfo.text}
                </span>
                <span className="finding-meta-dot" aria-hidden="true">•</span>
                <span className="finding-asset-name" title={primaryName}>
                  {primaryName}
                </span>
              </div>

              {secondaryId && secondaryId !== primaryName && (
                <div className="finding-secondary-asset-row">
                  <span className="finding-asset-id" title={secondaryId}>
                    {secondaryId}
                  </span>
                </div>
              )}

              {/* Telemetry Badges */}
              <div className="finding-telemetry-grid">
                <div className="finding-telemetry-row">
                  {isKev && (
                    <span className="ft-badge pink" title="Cataloged in CISA Known Exploited Vulnerabilities">
                      <Flame size={12} aria-hidden="true" /> Known Exploited (KEV)
                    </span>
                  )}
                  {epss != null && (
                    <span className="ft-badge peach" title={`EPSS Exploit Prediction: ${(epss * 100).toFixed(1)}%`}>
                      EPSS {(epss * 100).toFixed(0)}%
                    </span>
                  )}
                  {isInternet && (
                    <span className="ft-badge blue" title="Asset is directly accessible from the public Internet">
                      <Globe size={12} aria-hidden="true" /> Internet-facing
                    </span>
                  )}
                  <span className="ft-badge green" title={`Detected by ${scannerCount} of ${totalScanners} configured upstream scanners`}>
                    <CheckCircle2 size={12} aria-hidden="true" /> Detected by {scannerCount} of {totalScanners} scanners
                  </span>
                  <span className={confInfo.badgeClass} title={`Confidence classification: ${confInfo.label}`}>
                    <Shield size={12} aria-hidden="true" /> {confInfo.label}
                  </span>
                </div>
              </div>
            </div>

            {/* 4. Why It Matters Section */}
            <div className="finding-why-matters-col" onClick={(e) => e.stopPropagation()}>
              <div className="why-header">
                <Lightbulb size={15} className="why-icon" aria-hidden="true" />
                <span className="why-title">Why it matters</span>
              </div>
              <p className="why-desc" title={whyMattersText}>
                {whyMattersText}
              </p>
            </div>

            {/* 5. SLA Status & Actions Column */}
            <div className="finding-actions-col" onClick={(e) => e.stopPropagation()}>
              {/* SLA Tag */}
              <div className="f-sla-group">
                <span className={slaInfo.className}>
                  {slaInfo.label}
                </span>
                {slaInfo.timeText && (
                  <div className="f-sla-time">
                    <Clock size={11} aria-hidden="true" />
                    <span>{slaInfo.timeText}</span>
                  </div>
                )}
              </div>

              {/* Action Button */}
              <div className="f-btn-group">
                <button
                  className="f-investigate-btn"
                  onClick={(e) => handleInvestigate(f.finding_id, e)}
                  id={`btn-investigate-${f.finding_id.toLowerCase()}`}
                  aria-label={`Investigate finding ${f.finding_id}`}
                >
                  <span>Investigate</span>
                  <ArrowRight size={14} aria-hidden="true" />
                </button>
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}
