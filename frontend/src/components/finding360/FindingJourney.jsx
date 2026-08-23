import React, { useState } from 'react';
import { Check, Clock, Search, Zap, Target, FileText, UserCheck, CheckCircle2 } from 'lucide-react';

const STAGE_META = {
  DETECTED:    { icon: Search,       label: 'Detected',    module: 'M1 Scanner Ingestion' },
  CORRELATED:  { icon: Zap,          label: 'Correlated',  module: 'M2 Deduplication' },
  VALIDATED:   { icon: Check,        label: 'Validated',   module: 'M3 Confidence' },
  ENRICHED:    { icon: Target,       label: 'Enriched',    module: 'M4 Threat Intel' },
  PRIORITIZED: { icon: FileText,     label: 'Prioritized', module: 'M5 Risk Scoring' },
  EXPLAINED:   { icon: FileText,     label: 'Explained',   module: 'M6 Explainability' },
  ASSIGNED:    { icon: UserCheck,    label: 'Assigned',    module: 'M7 SLA Automation' },
  REMEDIATED:  { icon: CheckCircle2, label: 'Remediated',  module: 'M7/M8 Resolution' },
};

function getStageDetail(stage, finding) {
  const ti = finding?.detail?.threat_intelligence  ?? {};
  const sc = finding?.detail?.scanner_consensus     ?? {};
  const fc = finding?.detail?.finding_confidence    ?? {};
  const ex = finding?.detail?.explanation           ?? {};
  const wf = finding?.workflow                       ?? {};
  const prov = finding?.detail?.provenance           ?? {};

  switch (stage) {
    case 'DETECTED':
      return {
        heading: 'Original Scanner Ingestion (M1)',
        content: (prov.source_findings ?? []).length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {(prov.source_findings ?? []).map(sf => (
              <div key={sf.finding_id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="chip chip-blue">{sf.scanner}</span>
                <span className="text-mono" style={{ color: 'var(--text-secondary)' }}>{sf.finding_id}</span>
              </div>
            ))}
          </div>
        ) : <span className="text-muted">No raw scanner findings attached.</span>,
      };

    case 'CORRELATED':
      return {
        heading: 'Scanner Deduplication & Consensus (M2)',
        content: (
          <div>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 8 }}>
              {sc.detected_by_count ?? 0} of {sc.total_scanners ?? 3} independent scanners detected this vulnerability.
              Upstream M2 correlated them into single finding <strong className="text-mono">{finding?.finding_id}</strong>.
            </p>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {(sc.scanner_names ?? []).map(s => (
                <span key={s} className="chip chip-teal">{s}</span>
              ))}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              Consensus Score: <strong>{((sc.score ?? 0) * 100).toFixed(0)}%</strong>
            </div>
          </div>
        ),
      };

    case 'VALIDATED':
      return {
        heading: 'Noise Filter & Confidence Classification (M3)',
        content: (
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
              <span>Classification:</span>
              <strong>{fc.classification ?? '—'}</strong>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
              Confidence Score: <strong>{((fc.score ?? 0) * 100).toFixed(0)}%</strong>
            </div>
          </div>
        ),
      };

    case 'ENRICHED':
      return {
        heading: 'Threat Intelligence Enrichment (M4)',
        content: (
          <div className="detail-fields-grid">
            <div><span className="text-muted">CVSS v3.1:</span> <strong>{ti.cvss_score ?? 'N/A'}</strong></div>
            <div><span className="text-muted">EPSS:</span> <strong>{ti.epss_score != null ? `${(ti.epss_score * 100).toFixed(0)}%` : 'N/A'}</strong></div>
            <div><span className="text-muted">CISA KEV:</span> <strong>{ti.kev_listed ? '⚠ Listed' : 'Not Listed'}</strong></div>
            <div><span className="text-muted">Exploit:</span> <strong>{ti.exploit_available ? '⚠ Public Exploit' : 'None'}</strong></div>
          </div>
        ),
      };

    case 'PRIORITIZED':
      return {
        heading: 'Dynamic Risk Prioritization (M5)',
        content: (
          <div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 8 }}>
              Calculated Risk Score: <strong style={{ fontSize: 18, color: 'var(--risk-critical)' }}>{finding?.risk_score}</strong> / 100 ({finding?.risk_level})
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Engine version: {finding?.detail?.risk_assessment?.scoring_version ?? '—'}. Score visualized directly in M8.
            </div>
          </div>
        ),
      };

    case 'EXPLAINED':
      return {
        heading: 'Explainable AI Context (M6)',
        content: (
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            <strong>Technical:</strong> {ex.technical ?? '—'}
          </div>
        ),
      };

    case 'ASSIGNED':
      return {
        heading: 'SLA Automation & Ticketing (M7)',
        content: (
          <div className="detail-fields-grid">
            <div><span className="text-muted">Ticket ID:</span> <strong className="text-mono">{wf.ticket_id ?? 'N/A'}</strong></div>
            <div><span className="text-muted">Assigned Owner:</span> <strong>{wf.assigned_to ?? 'Unassigned'}</strong></div>
            <div><span className="text-muted">SLA Status:</span> <strong>{wf.sla_status ?? '—'}</strong></div>
            <div><span className="text-muted">Escalation:</span> <strong>Level {wf.escalation_level ?? 0}</strong></div>
          </div>
        ),
      };

    case 'REMEDIATED':
      return {
        heading: 'Resolution Status (M7/M8)',
        content: (
          <div style={{ fontSize: 13, color: wf.status === 'RESOLVED' ? 'var(--risk-low)' : 'var(--text-muted)' }}>
            {wf.status === 'RESOLVED' ? '✅ Marked as Resolved.' : 'Remediation currently in progress.'}
          </div>
        ),
      };

    default:
      return { heading: stage, content: null };
  }
}

export default function FindingJourney({ finding }) {
  const [activeStage, setActiveStage] = useState(null);

  const journey = finding?.detail?.provenance?.journey ?? [];
  const allStages = Object.keys(STAGE_META);

  const stages = allStages.map(s => {
    const match = journey.find(j => j.stage === s);
    return { stage: s, status: match?.status ?? 'PENDING' };
  });

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Finding Journey</div>
          <div className="card-subtitle">Trace decision provenance from scanner ingestion to remediation — click any node</div>
        </div>
      </div>
      <div className="card-body">
        <div className="journey-container">
          {stages.map(({ stage, status }, i) => {
            const Meta = STAGE_META[stage] ?? {};
            const Icon = Meta.icon ?? Clock;
            const isDone = status === 'DONE';
            const isActive = activeStage === stage;

            return (
              <div key={stage} className="journey-step-wrapper">
                <div
                  id={`journey-step-${stage.toLowerCase()}`}
                  className={`journey-step${isDone ? ' done' : ''}${isActive ? ' active' : ''}`}
                  onClick={() => setActiveStage(isActive ? null : stage)}
                >
                  <div className="journey-step-dot">
                    <Icon size={14} />
                  </div>
                  <div className="journey-step-label">{Meta.label}</div>
                  <div style={{ fontSize: 9, color: 'var(--text-faint)' }}>
                    {Meta.module?.split(' ')[0]}
                  </div>
                </div>

                {i < stages.length - 1 && (
                  <div className={`journey-connector${isDone ? ' done' : ''}`} />
                )}
              </div>
            );
          })}
        </div>

        {activeStage && (() => {
          const { heading, content } = getStageDetail(activeStage, finding);
          const Meta = STAGE_META[activeStage] ?? {};
          return (
            <div className="journey-detail-panel">
              <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--color-purple)', marginBottom: 2 }}>{heading}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>{Meta.module}</div>
              {content}
            </div>
          );
        })()}
      </div>
    </div>
  );
}
