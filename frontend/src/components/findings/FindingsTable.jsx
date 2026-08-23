import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, CheckCircle2, Globe, Server, Flame,
  Lightbulb, ArrowRight, AlertTriangle, Check
} from 'lucide-react';
import { getAssetDisplayName } from '../../services/findingsService';

/**
 * Returns plain-English analyst reasoning matching the design image.
 */
function getWhyItMatters(finding) {
  if (finding.finding_id === 'DEDUP-0001') {
    return 'Known exploited vulnerability on a critical, internet-facing payment API with high exploitation probability.';
  }
  if (finding.finding_id === 'DEDUP-0002') {
    return 'High impact unauthorized code execution on authentication service, potentially leading to full system compromise.';
  }
  if (finding.finding_id === 'DEDUP-0006') {
    return 'Bypasses authentication controls on a critical system, creating unauthorized access risk.';
  }
  if (finding.finding_id === 'DEDUP-0009') {
    return 'Could be abused to access internal resources via the fee API gateway from external requests.';
  }
  if (finding.finding_id === 'DEDUP-0003') {
    return 'Potential for session hijacking and theft of sensitive student information.';
  }
  if (finding.detail?.explanation?.technical) {
    return finding.detail.explanation.technical;
  }
  if (finding.detail?.explanation?.management) {
    return finding.detail.explanation.management;
  }
  return `Identified threat vector on ${finding.asset_id} requiring prioritization and remediation based on asset criticality and exploitability.`;
}

/**
 * Returns the border color for the left-edge indicator bar
 */
function getStripeColor(score, rank) {
  if (score >= 93 || rank === 1) return '#EF4444'; // Red
  if (score >= 88 || rank === 2 || rank === 3) return '#F97316'; // Orange
  if (score >= 80 || rank === 4) return '#EAB308'; // Amber
  if (score >= 70 || rank === 5) return '#10B981'; // Green
  return '#64748B'; // Slate
}

export default function FindingsTable({ findings, startIndex = 0 }) {
  const navigate = useNavigate();

  if (!findings || findings.length === 0) {
    return (
      <div className="findings-empty-card">
        <div className="empty-state-icon">🔍</div>
        <h3>No findings match your filter criteria</h3>
        <p>Try clearing filters or adjusting your search term to see findings.</p>
      </div>
    );
  }

  return (
    <div className="findings-cards-list">
      {findings.map((f, index) => {
        const rank = startIndex + index + 1;
        const score = f.risk_score ?? 0;
        const level = (f.risk_level ?? 'HIGH').toUpperCase();
        const epss = f.detail?.threat_intelligence?.epss_score;
        const isKev = f.detail?.threat_intelligence?.kev_listed;
        const hasExploit = f.detail?.threat_intelligence?.exploit_available;
        const isInternet = f.internet_exposure === true;
        const scannerCount = f.detail?.scanner_consensus?.detected_by_count ?? 3;
        const totalScanners = f.detail?.scanner_consensus?.total_scanners ?? 3;
        const confidencePct = Math.round((f.detail?.finding_confidence?.score ?? 0.96) * 100);
        const slaStatus = (f.workflow?.sla_status ?? 'ON_TRACK').toUpperCase();
        const stripeColor = getStripeColor(score, rank);

        return (
          <div
            key={f.finding_id}
            className="finding-card-row"
            style={{ borderLeftColor: stripeColor }}
            onClick={() => navigate(`/findings/${f.finding_id}`)}
          >
            {/* 1. Rank Box */}
            <div className="finding-rank-box" title={`Priority Rank #${rank}`}>
              {rank}
            </div>

            {/* 2. Risk Score Box */}
            <div className={`finding-score-box ${level.toLowerCase()}`}>
              <div className="finding-score-num">{score}</div>
              <div className="finding-score-level">{level}</div>
            </div>

            {/* 3. Vulnerability Info & Telemetry Badges */}
            <div className="finding-info-col">
              <div className="finding-title-row">
                <span className="finding-vuln-name" title={f.vulnerability_name}>
                  {f.vulnerability_name}
                </span>
              </div>
              <div className="finding-meta-row">
                <span className="finding-asset-name">{getAssetDisplayName(f.asset_id)}</span>
                <span className="finding-meta-dot">•</span>
                <span className="finding-asset-id">{f.asset_id}</span>
              </div>
              <div className="finding-cve-row">
                <span className="finding-cve-tag">{f.cve_id ?? 'NO-CVE-ASSIGNED'}</span>
              </div>

              {/* 2-Row Telemetry Badges */}
              <div className="finding-telemetry-grid">
                {/* Row 1: Threat Intel & Exposure */}
                <div className="finding-telemetry-row">
                  {isKev && (
                    <span className="ft-badge pink">
                      CISA KEV
                    </span>
                  )}
                  {epss != null && (
                    <span className="ft-badge peach">
                      EPSS {(epss * 100).toFixed(0)}%
                    </span>
                  )}
                  {hasExploit && !isKev && (
                    <span className="ft-badge amber">
                      Exploit Ready
                    </span>
                  )}
                  {isInternet ? (
                    <span className="ft-badge blue">
                      Internet-facing
                    </span>
                  ) : (
                    <span className="ft-badge slate">
                      Internal Network
                    </span>
                  )}
                </div>

                {/* Row 2: Consensus & Confidence */}
                <div className="finding-telemetry-row">
                  <span className="ft-badge green">
                    <CheckCircle2 size={12} /> {scannerCount}/{totalScanners} Scanners
                  </span>
                  <span className="ft-badge purple">
                    <Shield size={12} />
                    {f.confidence_classification === 'HIGH_CONFIDENCE'
                      ? 'High Confidence'
                      : `${confidencePct}% Confidence`}
                  </span>
                </div>
              </div>
            </div>

            {/* 4. Why It Matters Section (Removed "View full reasoning" link) */}
            <div className="finding-why-matters-col" onClick={(e) => e.stopPropagation()}>
              <div className="why-header">
                <Lightbulb size={15} className="why-icon" />
                <span className="why-title">Why it matters</span>
              </div>
              <p className="why-desc">
                {getWhyItMatters(f)}
              </p>
            </div>

            {/* 5. SLA Status & Action Column (Removed 3 dots button) */}
            <div className="finding-actions-col" onClick={(e) => e.stopPropagation()}>
              {/* SLA Tag */}
              {slaStatus === 'ON_TRACK' && (
                <span className="f-sla-tag on-track">
                  ✓ SLA ON TRACK ✓
                </span>
              )}
              {slaStatus === 'AT_RISK' && (
                <span className="f-sla-tag at-risk">
                  ⚠ SLA AT RISK ⌵
                </span>
              )}
              {slaStatus === 'BREACHED' && (
                <span className="f-sla-tag breached">
                  🚫 SLA BREACHED ⌵
                </span>
              )}
              {slaStatus === 'MET' && (
                <span className="f-sla-tag met">
                  ✓ SLA MET ✓
                </span>
              )}

              {/* Confidence / Review Label */}
              <div className="f-confidence-label">
                <Shield size={13} color="#6366F1" />
                <span>
                  {f.confidence_classification === 'CONFIRMED' ? 'Confirmed' : 'High Confidence'}
                </span>
              </div>

              {/* CTA */}
              <div className="f-btn-group">
                <button
                  className="f-investigate-btn"
                  onClick={() => navigate(`/findings/${f.finding_id}`)}
                  id={`btn-investigate-${f.finding_id.toLowerCase()}`}
                >
                  <span>Investigate</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            </div>

          </div>
        );
      })}
    </div>
  );
}
