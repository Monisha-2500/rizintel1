import React from 'react';
import { getAssetDisplayName } from '../../services/findingsService';
import { RiskBadge, BooleanBadge } from '../common/Badges';

export default function BlastRadius({ selectedAsset, findings }) {
  if (!selectedAsset) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">Blast Radius & Affected Assets</div>
        </div>
        <div className="card-body">
          <div className="empty-state" style={{ padding: 'var(--space-6)' }}>
            <div className="empty-state-icon">📡</div>
            <h3>Select an asset</h3>
            <p>Click on any asset to analyze its vulnerability exposure.</p>
          </div>
        </div>
      </div>
    );
  }

  // Find all findings affecting the selected asset
  const assetFindings = findings.filter(f => f.asset_id === selectedAsset.asset_id);

  // Group other assets exposed to the same vulnerabilities (Shared Exposure)
  const sharedExposures = [];
  assetFindings.forEach(f => {
    if (!f.vulnerability_type) return;
    const identicals = findings.filter(
      other => other.vulnerability_type === f.vulnerability_type && other.asset_id !== selectedAsset.asset_id
    );
    identicals.forEach(ident => {
      if (!sharedExposures.some(se => se.asset_id === ident.asset_id)) {
        sharedExposures.push({
          asset_id:         ident.asset_id,
          display_name:     getAssetDisplayName(ident.asset_id),
          vulnerability:    f.vulnerability_name,
          vuln_type:        f.vulnerability_type,
          asset_criticality:ident.asset_criticality,
          risk_score:       ident.risk_score,
        });
      }
    });
  });

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Affected Asset View — Blast Radius</div>
          <div className="card-subtitle">Vulnerabilities affecting {selectedAsset.display_name}</div>
        </div>
      </div>
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div>
          <div className="section-title">Vulnerabilities on Asset ({assetFindings.length})</div>
          <div className="table-wrapper" style={{ boxShadow: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Vulnerability</th>
                  <th>Type</th>
                  <th>Risk Score</th>
                  <th>SLA</th>
                </tr>
              </thead>
              <tbody>
                {assetFindings.map(f => (
                  <tr key={f.finding_id}>
                    <td style={{ fontWeight: 600 }}>{f.vulnerability_name}</td>
                    <td className="text-mono">{f.vulnerability_type}</td>
                    <td>
                      <span className="risk-score-pill critical" style={{ fontSize: 11, padding: '2px 6px' }}>
                        {f.risk_score}
                      </span>
                    </td>
                    <td>{f.workflow?.sla_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <div className="section-title">Shared Exposure (Other Assets with Same Vulnerability Types)</div>
          {sharedExposures.length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
              No other assets are exposed to the same vulnerability types.
            </p>
          ) : (
            <div className="table-wrapper" style={{ boxShadow: 'none' }}>
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Vulnerability Type</th>
                    <th>Crit.</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {sharedExposures.map(se => (
                    <tr key={se.asset_id}>
                      <td style={{ fontWeight: 600 }}>{se.display_name}</td>
                      <td className="text-mono">{se.vuln_type}</td>
                      <td><RiskBadge level={se.asset_criticality} /></td>
                      <td>
                        <span className="risk-score-pill high" style={{ fontSize: 11, padding: '2px 6px' }}>
                          {se.risk_score}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
