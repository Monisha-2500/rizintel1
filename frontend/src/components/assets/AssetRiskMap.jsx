import React from 'react';
import { RiskBadge, BooleanBadge } from '../common/Badges';
import { riskColor } from '../../utils/riskColors';
import { Globe, Server, AlertTriangle } from 'lucide-react';

export default function AssetRiskMap({ assets, selectedAsset, onSelectAsset }) {
  if (!assets || assets.length === 0) return null;

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Asset Risk Landscape</div>
          <div className="card-subtitle">Node size represents finding volume · Border color represents highest risk</div>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {assets.length} assets mapped
        </span>
      </div>
      <div className="card-body">
        <div className="asset-map-container">
          {assets.map(asset => {
            const isSelected = selectedAsset?.asset_id === asset.asset_id;
            const count = asset.findings.length;
            // Size scaled between 70px and 120px based on count
            const size = Math.min(120, Math.max(74, 60 + count * 14));
            const color = riskColor(
              asset.highest_risk >= 85 ? 'CRITICAL' : asset.highest_risk >= 70 ? 'HIGH' : asset.highest_risk >= 40 ? 'MEDIUM' : 'LOW'
            );

            return (
              <div
                key={asset.asset_id}
                id={`asset-bubble-${asset.asset_id.toLowerCase()}`}
                className={`asset-bubble${isSelected ? ' selected' : ''}`}
                onClick={() => onSelectAsset(asset)}
              >
                <div
                  className="asset-bubble-circle"
                  style={{
                    width: size,
                    height: size,
                    borderColor: color,
                    background: `radial-gradient(circle at 30% 30%, ${color}EE, ${color})`,
                  }}
                >
                  <div className="asset-bubble-score">{asset.highest_risk}</div>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.85)', fontWeight: 600 }}>
                    {count} finding{count !== 1 ? 's' : ''}
                  </div>
                </div>

                <div className="asset-bubble-name">
                  {asset.display_name}
                </div>

                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', justifyContent: 'center' }}>
                  {asset.internet_facing && (
                    <span className="chip chip-medium" style={{ fontSize: 9, padding: '1px 6px' }}>
                      <Globe size={9} /> Facing
                    </span>
                  )}
                  <RiskBadge level={asset.criticality} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
