import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { RISK_DISTRIBUTION_COLORS } from '../../utils/riskColors';

export default function RiskDonut({ summary }) {
  if (!summary) return null;

  const data = [
    { name: 'Critical', value: summary.critical ?? 0, color: RISK_DISTRIBUTION_COLORS.CRITICAL },
    { name: 'High',     value: summary.high     ?? 0, color: RISK_DISTRIBUTION_COLORS.HIGH },
    { name: 'Medium',   value: summary.medium   ?? 0, color: RISK_DISTRIBUTION_COLORS.MEDIUM },
    { name: 'Low',      value: summary.low      ?? 0, color: RISK_DISTRIBUTION_COLORS.LOW },
  ].filter(d => d.value > 0);

  const total = data.reduce((s, d) => s + d.value, 0);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload?.length) {
      const d = payload[0].payload;
      return (
        <div style={{
          background: 'white', border: '1px solid var(--border-color)',
          borderRadius: 8, padding: '8px 12px', fontSize: 12, boxShadow: 'var(--shadow-md)'
        }}>
          <div style={{ fontWeight: 700, color: d.color }}>{d.name}</div>
          <div style={{ color: 'var(--text-secondary)' }}>{d.value} finding{d.value !== 1 ? 's' : ''}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
            {total > 0 ? ((d.value / total) * 100).toFixed(0) : 0}% of total
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Risk Distribution</div>
          <div className="card-subtitle">{total} unique findings</div>
        </div>
      </div>
      <div className="card-body">
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              paddingAngle={3}
              dataKey="value"
              strokeWidth={0}
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend
              iconType="circle"
              iconSize={8}
              formatter={(value, entry) => (
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', marginLeft: 4 }}>
                  {value} <strong style={{ color: 'var(--text-primary)' }}>({entry.payload.value})</strong>
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Breakdown rows */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
          {data.map(d => (
            <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%', background: d.color, flexShrink: 0
              }} />
              <span style={{ fontSize: 12, color: 'var(--text-secondary)', flex: 1 }}>{d.name}</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>{d.value}</span>
              <div style={{
                width: 80, height: 5, background: 'var(--bg-surface-2)',
                borderRadius: 3, overflow: 'hidden', border: '1px solid var(--border-light)'
              }}>
                <div style={{
                  width: `${total > 0 ? (d.value / total) * 100 : 0}%`,
                  height: '100%', background: d.color, borderRadius: 3,
                  transition: 'width 0.5s ease'
                }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
