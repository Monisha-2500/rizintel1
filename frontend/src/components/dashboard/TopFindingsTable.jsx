import React from 'react';
import { useNavigate } from 'react-router-dom';
import { RiskScorePill, RiskBadge, ConfidenceBadge, SLABadge, KEVBadge } from '../common/Badges';
import { getAssetDisplayName } from '../../services/findingsService';
import { riskLevelClass } from '../../utils/riskColors';

export default function TopFindingsTable({ topRisks, findings }) {
  const navigate = useNavigate();

  // Merge top_risks list with full finding data to get CVE etc.
  const rows = (topRisks ?? []).map(tr => {
    const full = (findings ?? []).find(f => f.finding_id === tr.finding_id) ?? tr;
    return { ...tr, ...full };
  });

  if (rows.length === 0) {
    return (
      <div className="card">
        <div className="card-header"><div className="card-title">Top Priority Findings</div></div>
        <div className="empty-state"><div className="empty-state-icon">🛡️</div><h3>No findings</h3></div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Top Priority Findings</div>
          <div className="card-subtitle">Highest risk — requires immediate attention</div>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={() => navigate('/findings')}>
          View All →
        </button>
      </div>
      <div className="table-wrapper" style={{ borderRadius: 0, border: 'none', boxShadow: 'none' }}>
        <table>
          <thead>
            <tr>
              <th>Score</th>
              <th>Level</th>
              <th>Vulnerability</th>
              <th>CVE</th>
              <th>Asset</th>
              <th>Confidence</th>
              <th>KEV</th>
              <th>SLA</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(row => {
              const level = (row.risk_level ?? '').toUpperCase();
              return (
                <tr
                  key={row.finding_id}
                  id={`top-finding-${row.finding_id}`}
                  className={`clickable row-${riskLevelClass(level)}`}
                  onClick={() => navigate(`/findings/${row.finding_id}`)}
                >
                  <td><RiskScorePill score={row.risk_score} level={row.risk_level} /></td>
                  <td><RiskBadge level={row.risk_level} /></td>
                  <td>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>
                      {row.vulnerability_name ?? '—'}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.finding_id}</div>
                  </td>
                  <td>
                    <span className="text-mono" style={{ color: 'var(--text-secondary)' }}>
                      {row.cve_id ?? '—'}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 500 }}>{getAssetDisplayName(row.asset_id)}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.asset_id}</div>
                  </td>
                  <td><ConfidenceBadge classification={row.confidence_classification} /></td>
                  <td><KEVBadge listed={row.detail?.threat_intelligence?.kev_listed} /></td>
                  <td><SLABadge status={row.sla_status} /></td>
                  <td>
                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {row.workflow?.status ?? '—'}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
