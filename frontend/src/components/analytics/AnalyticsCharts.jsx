import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

export default function AnalyticsCharts({ findings }) {
  if (!findings || findings.length === 0) return null;

  // 1. Workflow Status
  const statusCounts = findings.reduce((acc, f) => {
    const s = f.workflow?.status || 'OPEN';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});
  const statusData = Object.keys(statusCounts).map(k => ({ name: k, count: statusCounts[k] }));

  // 2. Asset Criticality
  const critCounts = findings.reduce((acc, f) => {
    const c = f.asset_criticality || 'UNKNOWN';
    acc[c] = (acc[c] || 0) + 1;
    return acc;
  }, {});
  const critData = Object.keys(critCounts).map(k => ({ name: k, count: critCounts[k] }));

  // 3. Internet Exposure
  const faceCounts = findings.reduce((acc, f) => {
    const key = f.internet_exposure ? 'Internet-Facing' : 'Internal Only';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const faceData = Object.keys(faceCounts).map(k => ({ name: k, count: faceCounts[k] }));

  // 4. KEV Listed
  const kevCounts = findings.reduce((acc, f) => {
    const key = f.detail?.threat_intelligence?.kev_listed ? 'CISA KEV Listed' : 'Not Listed';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const kevData = Object.keys(kevCounts).map(k => ({ name: k, count: kevCounts[k] }));

  // 5. Confidence Distribution
  const confCounts = findings.reduce((acc, f) => {
    const c = f.confidence_classification || 'UNKNOWN';
    acc[c] = (acc[c] || 0) + 1;
    return acc;
  }, {});
  const confData = Object.keys(confCounts).map(k => ({ name: k, count: confCounts[k] }));

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload?.length) {
      return (
        <div style={{
          background: 'white', border: '1px solid var(--border-color)',
          borderRadius: 8, padding: '6px 12px', fontSize: 12, boxShadow: 'var(--shadow-md)'
        }}>
          <div style={{ fontWeight: 700, color: 'var(--color-purple)' }}>{label}</div>
          <div style={{ color: 'var(--color-primary)' }}>{payload[0].value} findings</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="stack">
      <div className="grid-2">
        {/* Chart 1: Workflow Status */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Workflow Status</div>
              <div className="card-subtitle">Open vs In-Progress vs Resolved</div>
            </div>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={statusData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-light)" />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-secondary)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="var(--color-primary)" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, fontStyle: 'italic' }}>
              Insight: Most high-priority items remain in OPEN status awaiting assignment.
            </div>
          </div>
        </div>

        {/* Chart 2: Asset Criticality */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Asset Criticality Distribution</div>
              <div className="card-subtitle">Vulnerabilities grouped by asset importance</div>
            </div>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={critData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-light)" />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-secondary)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="var(--color-purple)" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, fontStyle: 'italic' }}>
              Insight: Critical assets absorb the majority of severe risk scores.
            </div>
          </div>
        </div>
      </div>

      <div className="grid-3">
        {/* Chart 3: Exposure */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Internet Exposure</div>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={faceData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-light)" />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="var(--risk-high)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, fontStyle: 'italic' }}>
              Most critical findings affect externally exposed assets.
            </div>
          </div>
        </div>

        {/* Chart 4: KEV */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">CISA KEV Catalog</div>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={kevData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-light)" />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="var(--risk-critical)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, fontStyle: 'italic' }}>
              Active exploitation confirmed for CISA KEV items.
            </div>
          </div>
        </div>

        {/* Chart 5: Confidence */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Confidence Distribution</div>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={confData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-light)" />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="var(--color-teal)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, fontStyle: 'italic' }}>
              Scanner consensus validates high-confidence findings.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
