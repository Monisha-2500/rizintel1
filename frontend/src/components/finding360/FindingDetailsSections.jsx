import React from 'react';
import { getAssetDisplayName } from '../../services/findingsService';
import { RiskBadge, BooleanBadge } from '../common/Badges';

export function OverviewSection({ finding }) {
  const ac = finding.detail?.asset_context ?? {};
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Overview & Asset Context</div></div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {[
            { label: 'Vulnerability Type', value: finding.vulnerability_type ?? '—' },
            { label: 'Asset Name',          value: getAssetDisplayName(finding.asset_id) },
            { label: 'Asset ID',            value: finding.asset_id ?? '—', isMono: true },
            { label: 'Environment',         value: ac.environment ?? '—' },
            { label: 'Asset Criticality',   value: <RiskBadge level={finding.asset_criticality} /> },
            { label: 'Internet Exposure',   value: <BooleanBadge value={finding.internet_exposure} trueLabel="Facing" falseLabel="Internal" dangerOnTrue /> },
            { label: 'Data Sensitivity',    value: ac.data_sensitivity ?? '—' },
            { label: 'Discovered At',       value: finding.discovered_at ? new Date(finding.discovered_at).toLocaleString() : '—' },
          ].map(row => (
            <div key={row.label} style={{ borderBottom: '1px solid var(--border-light)', paddingBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>{row.label}</div>
              <div style={{ fontSize: 13, fontWeight: 600, fontFamily: row.isMono ? 'var(--font-mono)' : 'inherit' }}>{row.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ThreatIntelSection({ finding }) {
  const ti = finding.detail?.threat_intelligence ?? {};
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Threat Intelligence Enrichment (M4)</div></div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {[
            { label: 'CVSS v3.1 Score',      value: ti.cvss_score ?? '—' },
            { label: 'EPSS Probability',     value: ti.epss_score != null ? `${(ti.epss_score * 100).toFixed(0)}%` : '—' },
            { label: 'CISA KEV Catalog',     value: ti.kev_listed ? '⚠ Listed (Active exploitation detected)' : 'Not Listed' },
            { label: 'Exploit Availability', value: ti.exploit_available ? '⚠ Public exploit available' : 'None' },
          ].map(row => (
            <div key={row.label} style={{ borderBottom: '1px solid var(--border-light)', paddingBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>{row.label}</div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{row.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ScannerEvidenceSection({ finding }) {
  const sc = finding.detail?.scanner_consensus ?? {};
  const fc = finding.detail?.finding_confidence ?? {};
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Scanner Consensus & Evidence (M2/M3)</div></div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {[
            { label: 'Consensus Score',       value: sc.score != null ? `${(sc.score * 100).toFixed(0)}%` : '—' },
            { label: 'Detecting Scanners',    value: (sc.scanner_names ?? []).join(', ') || 'None' },
            { label: 'Scanners Reporting',    value: `${sc.detected_by_count ?? 0} of ${sc.total_scanners ?? 3}` },
            { label: 'Finding Confidence',    value: fc.classification ?? '—' },
          ].map(row => (
            <div key={row.label} style={{ borderBottom: '1px solid var(--border-light)', paddingBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>{row.label}</div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{row.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function RiskAssessmentSection({ finding }) {
  const ra = finding.detail?.risk_assessment ?? {};
  const breakdown = ra.score_breakdown ?? {};
  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Risk Assessment Breakdown (M5)</div>
          <div className="card-subtitle">Scoring engine: {ra.scoring_version}</div>
        </div>
      </div>
      <div className="card-body">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[
            { label: 'CVSS Contribution',        val: breakdown.cvss_contribution },
            { label: 'EPSS Contribution',        val: breakdown.epss_contribution },
            { label: 'KEV Contribution',         val: breakdown.kev_contribution },
            { label: 'Exploit Contribution',     val: breakdown.exploit_contribution },
            { label: 'Asset Criticality',        val: breakdown.asset_criticality_contribution },
            { label: 'Exposure Contribution',    val: breakdown.exposure_contribution },
            { label: 'Scanner Confidence',       val: breakdown.scanner_confidence_contribution },
          ].map(item => {
            const pct = Math.min(100, Math.max(0, (item.val / 30) * 100)); // Normalize max value around 30
            return (
              <div key={item.label} className="score-bar-row">
                <span className="score-bar-label">{item.label}</span>
                <div className="score-bar-track">
                  <div
                    className="score-bar-fill"
                    style={{ width: `${pct}%`, background: 'var(--color-blue)' }}
                  />
                </div>
                <span className="score-bar-value">+{item.val ?? 0}</span>
              </div>
            );
          })}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: 10, display: 'flex', justifyContent: 'space-between', fontWeight: 800 }}>
            <span>Total Risk Score</span>
            <span style={{ fontSize: 16, color: 'var(--risk-critical)' }}>{finding.risk_score} / 100</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ExplanationSection({ finding }) {
  const ex = finding.detail?.explanation ?? {};
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Explainable AI Advisor (M6)</div></div>
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div>
          <div className="section-title">Technical Explanation</div>
          <p style={{ fontSize: 13, color: 'var(--text-primary)', background: 'var(--bg-surface-2)', padding: 12, borderRadius: 6, border: '1px solid var(--border-light)' }}>
            {ex.technical ?? 'No technical explanation available.'}
          </p>
        </div>
        <div>
          <div className="section-title">Management Explanation</div>
          <p style={{ fontSize: 13, color: 'var(--text-primary)', background: 'var(--bg-surface-2)', padding: 12, borderRadius: 6, border: '1px solid var(--border-light)' }}>
            {ex.management ?? 'No management-friendly explanation available.'}
          </p>
        </div>
      </div>
    </div>
  );
}

export function RemediationSection({ finding }) {
  const wf = finding.workflow ?? {};
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Remediation & SLA Monitor (M7)</div></div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {[
            { label: 'Recommended Action', value: finding.recommended_action ?? '—' },
            { label: 'Ticket ID',          value: wf.ticket_id ?? '—', isMono: true },
            { label: 'Assigned Owner',     value: wf.assigned_to ?? 'Unassigned' },
            { label: 'SLA Duration (Hrs)', value: wf.sla_hours != null ? `${wf.sla_hours} hours` : '—' },
            { label: 'SLA Status',         value: wf.sla_status ?? '—' },
            { label: 'Escalation Level',   value: `Level ${wf.escalation_level ?? 0}` },
            { label: 'Workflow Status',    value: wf.status ?? '—' },
            { label: 'SLA Due At',         value: wf.sla_due_at ? new Date(wf.sla_due_at).toLocaleString() : '—' },
          ].map(row => (
            <div key={row.label} style={{ borderBottom: '1px solid var(--border-light)', paddingBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>{row.label}</div>
              <div style={{ fontSize: 13, fontWeight: 600, fontFamily: row.isMono ? 'var(--font-mono)' : 'inherit' }}>{row.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
