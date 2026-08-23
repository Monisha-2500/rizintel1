import React from 'react';
import { RiskBadge, BooleanBadge } from '../common/Badges';

export default function AssetCard({ asset, onClick }) {
  return (
    <div
      className="asset-card"
      id={`asset-card-${asset.asset_id.toLowerCase()}`}
      onClick={onClick}
    >
      <div className="asset-card-header">
        <div>
          <h3 className="asset-card-name">{asset.display_name}</h3>
          <span className="asset-card-id">{asset.asset_id}</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>
            {asset.highest_risk}
          </div>
          <span style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
            Highest Risk
          </span>
        </div>
      </div>

      <div className="asset-card-meta">
        <span className="tag">{asset.environment}</span>
        <RiskBadge level={asset.criticality} />
        <BooleanBadge value={asset.internet_facing} trueLabel="Facing" falseLabel="Internal" dangerOnTrue />
        {asset.data_sensitivity && asset.data_sensitivity !== 'UNKNOWN' && (
          <span className="tag" style={{ background: '#F5F3FF', color: '#6D28D9', borderColor: '#DDD6FE' }}>
            Data: {asset.data_sensitivity}
          </span>
        )}
      </div>

      <div className="asset-stats">
        <div className="asset-stat">
          <div className="asset-stat-value">{asset.findings.length}</div>
          <div className="asset-stat-label">Total</div>
        </div>
        <div className="asset-stat" style={{ borderLeft: '1px solid var(--border-light)', borderRight: '1px solid var(--border-light)' }}>
          <div className="asset-stat-value" style={{ color: 'var(--risk-critical)' }}>{asset.critical_count}</div>
          <div className="asset-stat-label">Critical</div>
        </div>
        <div className="asset-stat">
          <div className="asset-stat-value" style={{ color: 'var(--text-secondary)' }}>{asset.open_count}</div>
          <div className="asset-stat-label">Open</div>
        </div>
      </div>
    </div>
  );
}
