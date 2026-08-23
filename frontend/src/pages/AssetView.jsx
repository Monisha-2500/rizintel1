import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getAssets } from '../services/assetsService';
import {
  Globe, Shield, Server, Database, ChevronRight, X, TrendingUp,
  AlertTriangle, CheckCircle, Monitor, Star, ArrowRight, LayoutGrid,
  Search, SlidersHorizontal, Layers, ShieldCheck, List, Eye, EyeOff,
  ExternalLink, ArrowUpRight, Check, Copy, Sparkles
} from 'lucide-react';

/* ── Helper Color & Style Functions ────────────────────────────── */
function getRiskColor(score) {
  if (score >= 90) return { text: '#DC2626', bg: '#FEF2F2', border: '#FECACA', label: 'CRITICAL' };
  if (score >= 80) return { text: '#EA580C', bg: '#FFF7ED', border: '#FED7AA', label: 'HIGH' };
  if (score >= 60) return { text: '#CA8A04', bg: '#FEFCE8', border: '#FEF08A', label: 'MEDIUM' };
  return { text: '#16A34A', bg: '#F0FDF4', border: '#BBF7D0', label: 'LOW' };
}

function getAssetIcon(assetId = '', internetFacing = false) {
  if (assetId.includes('PAY') || assetId.includes('FEE')) return Globe;
  if (assetId.includes('AUTH') || assetId.includes('SVC')) return Shield;
  if (assetId.includes('ERP') || assetId.includes('FAC')) return Server;
  if (assetId.includes('PORTAL') || assetId.includes('STU')) return Monitor;
  if (assetId.includes('API')) return Database;
  return internetFacing ? Globe : Server;
}

function getIconColor(assetId = '') {
  if (assetId.includes('PAY') || assetId.includes('FEE')) return { bg: '#EFF6FF', color: '#3B82F6' };
  if (assetId.includes('AUTH') || assetId.includes('SVC')) return { bg: '#F5F3FF', color: '#8B5CF6' };
  if (assetId.includes('ERP') || assetId.includes('FAC')) return { bg: '#FFF7ED', color: '#F97316' };
  if (assetId.includes('PORTAL') || assetId.includes('STU')) return { bg: '#F0FDF4', color: '#22C55E' };
  return { bg: '#F1F5F9', color: '#64748B' };
}

/* ── Mini Sparkline Chart (7-day trend) ──────────────────────── */
function MiniTrendChart({ score }) {
  const points = useMemo(() => {
    const base = Math.max(score - 20, 30);
    const pts = [];
    for (let i = 0; i < 7; i++) {
      const progress = i / 6;
      const noise = (Math.sin(i * 1.5) * 4);
      pts.push(Math.min(100, Math.max(20, base + (score - base) * progress + noise)));
    }
    pts[6] = score;
    return pts;
  }, [score]);

  const W = 220, H = 65;
  const minP = Math.min(...points) - 5;
  const maxP = Math.max(...points) + 5;
  const toX = (i) => (i / 6) * (W - 24) + 12;
  const toY = (v) => H - ((v - minP) / (maxP - minP)) * (H - 16) - 8;

  const d = points.map((v, i) => `${i === 0 ? 'M' : 'L'} ${toX(i).toFixed(1)} ${toY(v).toFixed(1)}`).join(' ');
  const { text: lineColor } = getRiskColor(score);

  return (
    <div className="trend-chart-wrapper">
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} style={{ overflow: 'visible' }}>
        <defs>
          <linearGradient id={`trend-grad-${score}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={lineColor} stopOpacity="0.25" />
            <stop offset="100%" stopColor={lineColor} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path
          d={`${d} L ${toX(6)} ${H} L ${toX(0)} ${H} Z`}
          fill={`url(#trend-grad-${score})`}
        />
        <path d={d} fill="none" stroke={lineColor} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx={toX(6)} cy={toY(score)} r={4.5} fill={lineColor} />
      </svg>
      <div className="trend-chart-dates">
        <span>14 Aug</span>
        <span>16 Aug</span>
        <span>18 Aug</span>
        <span>20 Aug</span>
      </div>
    </div>
  );
}

/* ── Donut Chart for Risk Score Breakdown ──────────────────────── */
function RiskDonut() {
  const segments = [
    { label: 'Exploitability', pct: 50, color: '#EF4444' },
    { label: 'Exposure', pct: 30, color: '#F97316' },
    { label: 'Asset Criticality', pct: 10, color: '#8B5CF6' },
    { label: 'Threat Intel', pct: 10, color: '#3B82F6' },
  ];

  const R = 38, CX = 48, CY = 48, stroke = 12;
  let offset = 0;
  const circum = 2 * Math.PI * R;

  return (
    <div className="asset-donut-container">
      <svg width={96} height={96} viewBox="0 0 96 96" className="donut-svg">
        {segments.map((seg, i) => {
          const dashLen = (seg.pct / 100) * circum;
          const el = (
            <circle
              key={i}
              cx={CX} cy={CY} r={R}
              fill="none"
              stroke={seg.color}
              strokeWidth={stroke}
              strokeDasharray={`${dashLen} ${circum - dashLen}`}
              strokeDashoffset={-offset}
              transform={`rotate(-90 ${CX} ${CY})`}
              strokeLinecap="butt"
            />
          );
          offset += dashLen;
          return el;
        })}
      </svg>
      <div className="asset-donut-legend">
        {segments.map((s) => (
          <div key={s.label} className="donut-legend-item">
            <div className="donut-legend-dot" style={{ background: s.color }} />
            <span className="donut-legend-label">{s.label}</span>
            <span className="donut-legend-pct">{s.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Asset Card (Grid View) ──────────────────────────────────── */
function AssetCard({ asset, isSelected, onSelect }) {
  const risk = getRiskColor(asset.highest_risk);
  const AssetIcon = getAssetIcon(asset.asset_id, asset.internet_facing);
  const iconStyle = getIconColor(asset.asset_id);
  const hasCritical = asset.highest_risk >= 90;

  return (
    <div
      className={`asset-landscape-card ${isSelected ? 'selected' : ''}`}
      onClick={() => onSelect(asset)}
    >
      {/* Critical alert dot */}
      {hasCritical && <div className="asset-card-dot" title="Critical Risk Asset" />}

      <div className="asset-card-top">
        <div className="asset-card-icon-box" style={{ background: iconStyle.bg, color: iconStyle.color }}>
          <AssetIcon size={20} />
        </div>
        <div className="asset-card-info">
          <div className="asset-card-name" title={asset.display_name}>{asset.display_name}</div>
          <div className="asset-card-id">{asset.asset_id}</div>
        </div>
      </div>

      <div className="asset-card-score-row">
        <span className="asset-card-score" style={{ color: risk.text }}>{asset.highest_risk}</span>
        <span className="asset-card-level-pill" style={{ background: risk.bg, color: risk.text, border: `1px solid ${risk.border}` }}>
          {risk.label}
        </span>
      </div>

      <div className="asset-card-meta-row">
        <span className="asset-card-meta-item">
          {asset.internet_facing
            ? <><Globe size={13} /> Internet-Facing</>
            : <><Server size={13} /> Internal</>}
        </span>
        <span className="asset-card-meta-sep">•</span>
        <span className="asset-card-meta-item">{asset.findings.length} finding{asset.findings.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="asset-card-tags-group">
        {asset.data_sensitivity && asset.data_sensitivity !== 'UNKNOWN' && (
          <span className="asset-card-data-tag">{asset.data_sensitivity}</span>
        )}
        {asset.environment && asset.environment !== 'UNKNOWN' && (
          <span className="asset-card-env-tag">{asset.environment}</span>
        )}
      </div>
    </div>
  );
}

/* ── Asset Table View Component ──────────────────────────────── */
function AssetTableView({ assets, selectedAsset, onSelect, onInvestigate }) {
  return (
    <div className="asset-table-container">
      <table className="asset-full-table">
        <thead>
          <tr>
            <th>RANK</th>
            <th>ASSET</th>
            <th>HIGHEST RISK</th>
            <th>EXPOSURE</th>
            <th>ENVIRONMENT</th>
            <th>CRITICALITY</th>
            <th>FINDINGS</th>
            <th style={{ textAlign: 'right' }}>ACTION</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset, idx) => {
            const rank = String(idx + 1).padStart(2, '0');
            const risk = getRiskColor(asset.highest_risk);
            const AssetIcon = getAssetIcon(asset.asset_id, asset.internet_facing);
            const iconStyle = getIconColor(asset.asset_id);
            const isSelected = selectedAsset?.asset_id === asset.asset_id;

            return (
              <tr
                key={asset.asset_id}
                className={`asset-table-row ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelect(asset)}
              >
                <td>
                  <span className="asset-table-rank">{rank}</span>
                </td>
                <td>
                  <div className="asset-table-name-cell">
                    <div className="asset-table-icon-box" style={{ background: iconStyle.bg, color: iconStyle.color }}>
                      <AssetIcon size={16} />
                    </div>
                    <div>
                      <div className="asset-table-title">{asset.display_name}</div>
                      <div className="asset-table-id">{asset.asset_id}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <div className="asset-table-risk-cell">
                    <span className="asset-table-score-badge" style={{ background: risk.bg, color: risk.text, border: `1px solid ${risk.border}` }}>
                      {asset.highest_risk} {risk.label}
                    </span>
                    <div className="asset-table-bar-track">
                      <div
                        className="asset-table-bar-fill"
                        style={{ width: `${asset.highest_risk}%`, background: risk.text }}
                      />
                    </div>
                  </div>
                </td>
                <td>
                  <span className="asset-table-exposure-pill">
                    {asset.internet_facing ? <Globe size={13} color="#2563EB" /> : <Server size={13} color="#475569" />}
                    <span>{asset.internet_facing ? 'Internet-Facing' : 'Internal'}</span>
                  </span>
                </td>
                <td>
                  <span className="asset-table-env-badge">{asset.environment || 'Production'}</span>
                </td>
                <td>
                  <span className={`asset-table-crit-badge ${(asset.criticality || '').toLowerCase()}`}>
                    {asset.criticality || 'MEDIUM'}
                  </span>
                </td>
                <td>
                  <span className="asset-table-findings-count">
                    {asset.findings.length}
                  </span>
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="asset-table-inspect-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect(asset);
                    }}
                  >
                    Inspect <ChevronRight size={14} />
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ── Asset Inspector Left Sidebar Component ─────────────────── */
function AssetInspectorSidebar({ asset, onClose, onInvestigate }) {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'specs' | 'findings'
  const [copied, setCopied] = useState(false);

  if (!asset) return null;

  const risk = getRiskColor(asset.highest_risk);
  const IconComp = getAssetIcon(asset.asset_id, asset.internet_facing);
  const iconColor = getIconColor(asset.asset_id);
  const findings = asset.findings || [];
  const topFinding = findings[0];
  const topRisk = topFinding ? getRiskColor(topFinding.risk_score) : null;

  const handleCopyId = (e) => {
    e.stopPropagation();
    if (navigator.clipboard) {
      navigator.clipboard.writeText(asset.asset_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <aside className="asset-inspector-sidebar fade-in" aria-label="Asset Inspector">
      {/* Header */}
      <div className="aid-header">
        <div className="aid-header-top">
          <div className="aid-identity">
            <div 
              className="aid-icon-box"
              style={{ background: iconColor.bg, color: iconColor.color }}
            >
              <IconComp size={18} />
            </div>
            <div className="aid-title-wrap">
              <div className="aid-title-row">
                <h3 className="aid-title">{asset.display_name}</h3>
                <span 
                  className="aid-crit-pill"
                  style={{ background: risk.bg, color: risk.text, borderColor: risk.border }}
                >
                  {risk.label}
                </span>
              </div>
              <div className="aid-id-row">
                <span className="aid-id-code">{asset.asset_id}</span>
                <button 
                  className="aid-copy-btn" 
                  onClick={handleCopyId}
                  title="Copy Asset ID"
                >
                  {copied ? <Check size={11} color="#16A34A" /> : <Copy size={11} />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          <button 
            className="aid-close-btn" 
            onClick={onClose} 
            title="Hide Inspector"
          >
            <X size={16} />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="aid-tabs-nav">
          <button 
            className={`aid-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={`aid-tab-btn ${activeTab === 'specs' ? 'active' : ''}`}
            onClick={() => setActiveTab('specs')}
          >
            Specifications
          </button>
          <button 
            className={`aid-tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            Findings <span className="aid-tab-badge">{findings.length}</span>
          </button>
        </div>
      </div>

      {/* Scrollable Body */}
      <div className="aid-body-scroll">
        {activeTab === 'overview' && (
          <div className="aid-tab-content fade-in">
            {/* Score & Telemetry Hero Card */}
            <div className="aid-hero-card">
              <div className="aid-hero-main">
                <div className="aid-hero-score-orb" style={{ borderColor: risk.border }}>
                  <span className="aid-score-number" style={{ color: risk.text }}>
                    {asset.highest_risk}
                  </span>
                  <span className="aid-score-caption">RISK SCORE</span>
                </div>
                <div className="aid-hero-telemetry">
                  <div className="aid-telemetry-chip">
                    <span className="aid-chip-label">Exposure</span>
                    <span className={`aid-chip-val ${asset.internet_facing ? 'blue' : 'slate'}`}>
                      {asset.internet_facing ? '🌐 Internet-Facing' : '🔒 Internal'}
                    </span>
                  </div>
                  <div className="aid-telemetry-chip">
                    <span className="aid-chip-label">Environment</span>
                    <span className="aid-chip-val purple">
                      {asset.environment || 'Production'}
                    </span>
                  </div>
                  <div className="aid-telemetry-chip">
                    <span className="aid-chip-label">Data Sensitivity</span>
                    <span className="aid-chip-val purple">
                      {asset.data_sensitivity || 'Confidential'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="aid-hero-narrative">
                <p>
                  {asset.internet_facing
                    ? `Critical ${asset.environment?.toLowerCase() || 'production'} asset exposed to internet handling sensitive ${asset.data_sensitivity || 'confidential'} data.`
                    : `Internal ${asset.environment?.toLowerCase() || 'production'} asset with ${asset.critical_count} critical vulnerability requiring remediation.`}
                </p>
              </div>
            </div>

            {/* 7-Day Risk Trend Chart */}
            <div className="aid-section-card">
              <div className="aid-section-header">
                <TrendingUp size={14} color="#7C3AED" />
                <span>7-DAY RISK TRAJECTORY</span>
              </div>
              <MiniTrendChart score={asset.highest_risk} />
            </div>

            {/* Risk Score Breakdown Donut */}
            <div className="aid-section-card">
              <div className="aid-section-header">
                <Layers size={14} color="#7C3AED" />
                <span>RISK COMPOSITION BREAKDOWN</span>
              </div>
              <RiskDonut />
            </div>

            {/* Top Finding Spotlight */}
            {topFinding && topRisk && (
              <div className="aid-section-card spotlight">
                <div className="aid-section-header">
                  <AlertTriangle size={14} color={topRisk.text} />
                  <span>HIGHEST SEVERITY FINDING</span>
                </div>
                <div 
                  className="aid-spotlight-finding"
                  onClick={() => onInvestigate(topFinding.finding_id)}
                >
                  <div className="aid-spotlight-header">
                    <h4 className="aid-sf-title">{topFinding.vulnerability_name}</h4>
                    <span 
                      className="aid-sf-pill"
                      style={{ background: topRisk.bg, color: topRisk.text, borderColor: topRisk.border }}
                    >
                      {topFinding.risk_score} {topRisk.label}
                    </span>
                  </div>
                  <div className="aid-sf-meta">
                    <span>{topFinding.cve_id}</span>
                    <span>•</span>
                    <span>{topFinding.vulnerability_type}</span>
                  </div>
                  <button 
                    className="aid-sf-investigate-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      onInvestigate(topFinding.finding_id);
                    }}
                  >
                    <span>Investigate in Finding 360</span>
                    <ArrowRight size={13} />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'specs' && (
          <div className="aid-tab-content fade-in">
            <div className="aid-section-card">
              <div className="aid-section-header">
                <ShieldCheck size={14} color="#7C3AED" />
                <span>ASSET SPECIFICATIONS & METADATA</span>
              </div>
              <div className="aid-specs-list">
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Asset ID</span>
                  <span className="aid-spec-val mono">{asset.asset_id}</span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Asset Type</span>
                  <span className="aid-spec-val">
                    {asset.asset_id.includes('PAY') || asset.asset_id.includes('FEE') ? 'Payment Gateway / API' :
                     asset.asset_id.includes('AUTH') ? 'Authentication Service' :
                     asset.asset_id.includes('ERP') ? 'Enterprise Resource App' :
                     asset.asset_id.includes('PORTAL') ? 'Customer Web Portal' : 'Microservice / API'}
                  </span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Environment</span>
                  <span className="aid-spec-val">{asset.environment || 'Production'}</span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Business Owner</span>
                  <span className="aid-spec-val">Finance Tech Operations</span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Data Classification</span>
                  <span className="aid-spec-val">{asset.data_sensitivity || 'Confidential / PCI'}</span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Discovered Date</span>
                  <span className="aid-spec-val">20 Aug 2026, 13:40 IST</span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Total Detected Vulns</span>
                  <span className="aid-spec-val bold">{findings.length}</span>
                </div>
                <div className="aid-spec-row">
                  <span className="aid-spec-key">Critical Vulns</span>
                  <span className="aid-spec-val bold red">{asset.critical_count}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="aid-tab-content fade-in">
            <div className="aid-findings-stream">
              {findings.map((f) => {
                const fRisk = getRiskColor(f.risk_score);
                return (
                  <div 
                    key={f.finding_id}
                    className="aid-finding-item"
                    onClick={() => onInvestigate(f.finding_id)}
                  >
                    <div className="aid-fi-top">
                      <div className="aid-fi-title-box">
                        <span className="aid-fi-name">{f.vulnerability_name}</span>
                        <span className="aid-fi-cve">{f.cve_id}</span>
                      </div>
                      <span 
                        className="aid-fi-score-pill"
                        style={{ background: fRisk.bg, color: fRisk.text, borderColor: fRisk.border }}
                      >
                        {f.risk_score} {fRisk.label}
                      </span>
                    </div>
                    <div className="aid-fi-bottom">
                      <span className="aid-fi-type">{f.vulnerability_type}</span>
                      <button 
                        className="aid-fi-action-link"
                        onClick={(e) => {
                          e.stopPropagation();
                          onInvestigate(f.finding_id);
                        }}
                      >
                        <span>Inspect</span>
                        <ChevronRight size={13} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Sticky Footer */}
      <div className="aid-footer">
        {topFinding ? (
          <button 
            className="aid-primary-footer-btn"
            onClick={() => onInvestigate(topFinding.finding_id)}
          >
            <span>Investigate Top Finding</span>
            <ArrowRight size={14} />
          </button>
        ) : (
          <button className="aid-primary-footer-btn" onClick={onClose}>
            <span>Close Inspector</span>
          </button>
        )}
      </div>
    </aside>
  );
}

/* ── Main Asset View Page ────────────────────────────────────── */
export default function AssetView() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const targetAssetId = searchParams.get('asset') || searchParams.get('id');

  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [showInspector, setShowInspector] = useState(true); // Toggleable inspector sidebar
  const [viewMode, setViewMode] = useState('grid'); // 'grid' | 'table'
  const [activeFilter, setActiveFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    Promise.all([getAssets()]).then(([a]) => {
      setAssets(a);
      if (a.length > 0) {
        const cleanTarget = targetAssetId ? targetAssetId.toLowerCase().replace(/[^a-z0-9]/g, '') : '';
        const match = targetAssetId
          ? a.find(x =>
              x.asset_id?.toLowerCase() === targetAssetId.toLowerCase() ||
              x.display_name?.toLowerCase().includes(targetAssetId.toLowerCase()) ||
              (cleanTarget && x.asset_id?.toLowerCase().replace(/[^a-z0-9]/g, '').includes(cleanTarget)) ||
              (cleanTarget && cleanTarget.includes(x.asset_id?.toLowerCase().replace(/[^a-z0-9]/g, ''))) ||
              x.findings?.some(f => f.detail?.asset_context?.asset_name?.toLowerCase().includes(targetAssetId.toLowerCase()))
            )
          : null;
        setSelectedAsset(match || a[0]);
      }
      setLoading(false);
    });
  }, [targetAssetId]);

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    let list = [...assets];
    if (activeFilter === 'internet') list = list.filter(a => a.internet_facing);
    else if (activeFilter === 'critical') list = list.filter(a => (a.criticality || '').toUpperCase() === 'CRITICAL');
    else if (activeFilter === 'production') list = list.filter(a => (a.environment || '').toUpperCase() === 'PRODUCTION');

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(a =>
        a.display_name?.toLowerCase().includes(q) ||
        a.asset_id?.toLowerCase().includes(q) ||
        a.environment?.toLowerCase().includes(q) ||
        a.criticality?.toLowerCase().includes(q) ||
        a.data_sensitivity?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [assets, activeFilter, searchQuery]);

  const internetFacingAssets = filteredAssets.filter(a => a.internet_facing);
  const internalAssets = filteredAssets.filter(a => !a.internet_facing);

  const totalAssets = assets.length;
  const internetCount = assets.filter(a => a.internet_facing).length;
  const criticalCount = assets.filter(a => (a.criticality || '').toUpperCase() === 'CRITICAL').length;
  const needAttention = assets.filter(a => a.highest_risk >= 80).length;

  const handleSelectAsset = (asset) => {
    setSelectedAsset(asset);
    setShowInspector(true); // Automatically show inspector when an asset is clicked
  };

  const handleViewAllClick = () => {
    setActiveFilter('all');
    setSearchQuery('');
    setViewMode('table'); // Switch to full comprehensive table view with all 10 assets
  };

  if (loading) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚡</div>
        <h3>Loading Asset Risk Landscape…</h3>
      </div>
    );
  }

  const FILTERS = [
    { id: 'all', label: 'All Assets', icon: LayoutGrid },
    { id: 'internet', label: 'Internet-Facing', icon: Globe },
    { id: 'critical', label: 'Critical', icon: Shield },
    { id: 'production', label: 'Production', icon: Server },
  ];

  return (
    <div className="asset-page-outer-container">
      <div className="asset-page-inner-wrapper">

        <div className={`asset-page-layout-root ${showInspector && selectedAsset ? 'with-inspector' : 'full-width'}`}>

          {/* Left / Main Flow (Header, Filters, Landscape Cards / Table) */}
          <div className="asset-main-content-flow">

            {/* ── 1. Page Header Card ── */}
            <div className="asset-page-header-card">
              <div className="asset-page-header-left">
                <div className="asset-eyebrow">
                  <Sparkles size={13} /> Asset Intelligence
                </div>
                <h1 className="asset-page-title">Asset Risk Landscape</h1>
                <p className="asset-page-subtitle">
                  Understand where organizational vulnerability risk is concentrated across your environment.
                </p>
              </div>

              {/* KPI Stat Chips */}
              <div className="asset-header-kpi-row">
                <div className="asset-kpi-chip">
                  <div className="asset-kpi-val">{totalAssets}</div>
                  <div className="asset-kpi-label">Total Assets</div>
                </div>
                <div className="asset-kpi-chip">
                  <div className="asset-kpi-val">{internetCount}</div>
                  <div className="asset-kpi-label">Internet-Facing</div>
                </div>
                <div className="asset-kpi-chip">
                  <div className="asset-kpi-val red">{criticalCount}</div>
                  <div className="asset-kpi-label">Critical Assets</div>
                </div>
                <div className="asset-kpi-chip">
                  <div className="asset-kpi-val orange">{needAttention}</div>
                  <div className="asset-kpi-label">Need Attention</div>
                </div>
              </div>
            </div>

            {/* ── 2. Filter & Controls Bar ── */}
            <div className="asset-filter-bar-card">
              {/* Search Box */}
              <div className="asset-search-box">
                <Search size={15} className="asset-search-icon" />
                <input
                  type="text"
                  placeholder="Search assets, IDs or vulnerabilities..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="asset-search-input"
                />
                {searchQuery && (
                  <button className="search-clear-btn" onClick={() => setSearchQuery('')}>
                    <X size={13} />
                  </button>
                )}
              </div>

              {/* Filter Pills */}
              <div className="asset-filter-pills">
                {FILTERS.map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    className={`asset-filter-pill ${activeFilter === id ? 'active' : ''}`}
                    onClick={() => setActiveFilter(id)}
                  >
                    <Icon size={14} />
                    <span>{label}</span>
                  </button>
                ))}
              </div>

              {/* Right Controls: View Switcher & Inspector Toggle */}
              <div className="asset-right-controls-group">
                {/* Grid / Table Mode Switcher */}
                <div className="asset-view-mode-toggle">
                  <button
                    className={`view-mode-btn ${viewMode === 'grid' ? 'active' : ''}`}
                    onClick={() => setViewMode('grid')}
                    title="Cards Landscape View"
                  >
                    <LayoutGrid size={15} />
                    <span>Grid</span>
                  </button>
                  <button
                    className={`view-mode-btn ${viewMode === 'table' ? 'active' : ''}`}
                    onClick={() => setViewMode('table')}
                    title="All Assets Table View"
                  >
                    <List size={15} />
                    <span>Table</span>
                  </button>
                </div>

                {/* Adaptable Inspector Toggle Button */}
                <button
                  className={`asset-inspector-toggle-btn ${showInspector ? 'active' : ''}`}
                  onClick={() => setShowInspector(!showInspector)}
                  title={showInspector ? 'Hide Asset Inspector Panel' : 'Show Asset Inspector Panel'}
                >
                  {showInspector ? <EyeOff size={15} /> : <Eye size={15} />}
                  <span>{showInspector ? 'Hide Inspector' : 'Asset Inspector'}</span>
                  <span className="inspector-badge">{selectedAsset ? selectedAsset.display_name : '10'}</span>
                </button>
              </div>
            </div>

            {/* ── 3. Cards Grid OR Full Table ── */}
            {viewMode === 'grid' ? (
              <div className="asset-landscape-section">
                <div className="asset-landscape-header-row">
                  <div className="asset-landscape-label">
                    <LayoutGrid size={16} />
                    <span>ASSET RISK LANDSCAPE</span>
                    <span className="asset-landscape-note">
                      Node size represents finding volume • Border color represents highest risk
                    </span>
                  </div>

                  <button className="view-all-header-btn" onClick={handleViewAllClick}>
                    <span>View all {assets.length} assets</span>
                    <ArrowRight size={14} />
                  </button>
                </div>

                {/* Internet-Facing Group */}
                {internetFacingAssets.length > 0 && (
                  <div className="asset-group-section">
                    <div className="asset-group-label">
                      <Globe size={14} color="#2563EB" />
                      <span>INTERNET FACING ({internetFacingAssets.length})</span>
                    </div>
                    <div className="asset-cards-grid">
                      {internetFacingAssets.map(asset => (
                        <AssetCard
                          key={asset.asset_id}
                          asset={asset}
                          isSelected={selectedAsset?.asset_id === asset.asset_id}
                          onSelect={handleSelectAsset}
                        />
                      ))}
                    </div>
                  </div>
                )}

                {/* Internal Assets Group */}
                {internalAssets.length > 0 && (
                  <div className="asset-group-section">
                    <div className="asset-group-label">
                      <Server size={14} color="#475569" />
                      <span>INTERNAL ASSETS ({internalAssets.length})</span>
                    </div>
                    <div className="asset-cards-grid">
                      {internalAssets.map(asset => (
                        <AssetCard
                          key={asset.asset_id}
                          asset={asset}
                          isSelected={selectedAsset?.asset_id === asset.asset_id}
                          onSelect={handleSelectAsset}
                        />
                      ))}
                    </div>
                  </div>
                )}

                {filteredAssets.length === 0 && (
                  <div className="asset-empty-state">
                    <Search size={36} color="#94A3B8" />
                    <h4>No matching assets found</h4>
                    <p>Try clearing your search query or selecting "All Assets".</p>
                  </div>
                )}

                {/* Functional View All Button at the bottom */}
                <div className="asset-view-all-row">
                  <button className="asset-view-all-btn" onClick={handleViewAllClick}>
                    <span>View all {assets.length} assets in full detail</span>
                    <ArrowRight size={15} />
                  </button>
                </div>
              </div>
            ) : (
              /* Full Table View */
              <div className="asset-landscape-section">
                <div className="asset-landscape-header-row">
                  <div className="asset-landscape-label">
                    <List size={16} />
                    <span>ALL MONITORED ASSETS ({filteredAssets.length})</span>
                    <span className="asset-landscape-note">
                      Ranked by severity and business risk impact
                    </span>
                  </div>

                  <button className="view-all-header-btn" onClick={() => setViewMode('grid')}>
                    <LayoutGrid size={14} />
                    <span>Back to Cards Grid</span>
                  </button>
                </div>

                <AssetTableView
                  assets={filteredAssets}
                  selectedAsset={selectedAsset}
                  onSelect={handleSelectAsset}
                  onInvestigate={(findingId) => navigate(`/findings/${findingId}`)}
                />
              </div>
            )}

          </div>

          {/* ── Dedicated Full Right Column: Asset Inspector ── */}
          {showInspector && selectedAsset && (
            <div className="asset-inspector-col-root">
              <AssetInspectorSidebar
                asset={selectedAsset}
                onClose={() => setShowInspector(false)}
                onInvestigate={(findingId) => navigate(`/findings/${findingId}`)}
              />
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
