import React from 'react';

export default function KPICard({ label, value, sub, icon: Icon, color }) {
  return (
    <div className="kpi-card" id={`kpi-${label.toLowerCase().replace(/\s+/g, '-')}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="kpi-card-label">{label}</div>
          <div className="kpi-card-value">{value}</div>
          {sub && <div className="kpi-card-sub">{sub}</div>}
        </div>
        {Icon && (
          <div className="kpi-card-icon" style={{ background: color + '15', color: color }}>
            <Icon size={18} />
          </div>
        )}
      </div>
    </div>
  );
}
