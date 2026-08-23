import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { getSLAItems } from '../services/slaService';
import {
  Clock, AlertTriangle, AlertCircle, CheckCircle2, ShieldCheck,
  Zap, Shield, Code, Globe, Server, Database, ArrowUpRight,
  ArrowRight, Sparkles, TrendingUp, TrendingDown, Flame,
  Activity, Target, Timer, BarChart2, Users, Layers, Eye
} from 'lucide-react';

/* ── Curated SLA Dataset ── */
const DEFAULT_SLA_FINDINGS = [
  {
    finding_id: 'DEDUP-0006',
    vulnerability_name: 'Authentication Bypass',
    cve_id: 'CVE-2026-4432',
    ticket_id: 'VULN-0006',
    risk_score: 88,
    risk_level: 'CRITICAL',
    asset_name: 'Faculty ERP',
    asset_type: 'Web App',
    owner: 'erpteam',
    owner_avatar: 'ER',
    owner_color: '#4338CA',
    owner_bg: '#E0E7FF',
    time_remaining: 'Breached 47m ago',
    time_type: 'breached',
    sla_status: 'BREACHED',
    escalation_level: 'Lvl 1',
    icon_type: 'shield',
    sla_pct: 0,
  },
  {
    finding_id: 'DEDUP-0002',
    vulnerability_name: 'Remote Code Execution',
    cve_id: 'CVE-2025-7788',
    ticket_id: 'VULN-0002',
    risk_score: 91,
    risk_level: 'CRITICAL',
    asset_name: 'Auth Service',
    asset_type: 'Microservice',
    owner: 'secops',
    owner_avatar: 'SE',
    owner_color: '#7E22CE',
    owner_bg: '#F3E8FF',
    time_remaining: '01h 24m left',
    time_type: 'at_risk',
    sla_status: 'AT RISK',
    escalation_level: 'Lvl 1',
    icon_type: 'code',
    sla_pct: 12,
  },
  {
    finding_id: 'DEDUP-0009',
    vulnerability_name: 'Server-Side Request Forgery',
    cve_id: 'CVE-2026-3391',
    ticket_id: 'VULN-0009',
    risk_score: 84,
    risk_level: 'HIGH',
    asset_name: 'Fee API Gateway',
    asset_type: 'API Gateway',
    owner: 'payments',
    owner_avatar: 'PA',
    owner_color: '#15803D',
    owner_bg: '#DCFCE7',
    time_remaining: '03h 12m left',
    time_type: 'at_risk',
    sla_status: 'AT RISK',
    escalation_level: 'Lvl 2',
    icon_type: 'globe',
    sla_pct: 32,
  },
  {
    finding_id: 'DEDUP-0001',
    vulnerability_name: 'SQL Injection',
    cve_id: 'CVE-2026-1234',
    ticket_id: 'VULN-0001',
    risk_score: 94,
    risk_level: 'CRITICAL',
    asset_name: 'Fee Payment API',
    asset_type: 'Payment Service',
    owner: 'payments',
    owner_avatar: 'PA',
    owner_color: '#15803D',
    owner_bg: '#DCFCE7',
    time_remaining: '09h 32m left',
    time_type: 'on_track',
    sla_status: 'ON TRACK',
    escalation_level: '—',
    icon_type: 'database',
    sla_pct: 72,
  },
  {
    finding_id: 'DEDUP-0003',
    vulnerability_name: 'Cross-Site Scripting',
    cve_id: 'CVE-2026-2211',
    ticket_id: 'VULN-0003',
    risk_score: 78,
    risk_level: 'HIGH',
    asset_name: 'Student Portal',
    asset_type: 'Web Portal',
    owner: 'webteam',
    owner_avatar: 'WB',
    owner_color: '#1D4ED8',
    owner_bg: '#DBEAFE',
    time_remaining: '21h 18m left',
    time_type: 'on_track',
    sla_status: 'ON TRACK',
    escalation_level: '—',
    icon_type: 'code',
    sla_pct: 58,
  },
  {
    finding_id: 'DEDUP-0007',
    vulnerability_name: 'Hardcoded Crypto Key',
    cve_id: 'CVE-2026-5541',
    ticket_id: 'VULN-0007',
    risk_score: 72,
    risk_level: 'MEDIUM',
    asset_name: 'Core Banking API',
    asset_type: 'Core API',
    owner: 'secops',
    owner_avatar: 'SE',
    owner_color: '#7E22CE',
    owner_bg: '#F3E8FF',
    time_remaining: '48h left',
    time_type: 'on_track',
    sla_status: 'ON TRACK',
    escalation_level: '—',
    icon_type: 'shield',
    sla_pct: 65,
  },
  {
    finding_id: 'DEDUP-0010',
    vulnerability_name: 'Directory Traversal',
    cve_id: 'CVE-2026-6672',
    ticket_id: 'VULN-0010',
    risk_score: 65,
    risk_level: 'MEDIUM',
    asset_name: 'Document Repository',
    asset_type: 'File Storage',
    owner: 'infra',
    owner_avatar: 'IN',
    owner_color: '#B45309',
    owner_bg: '#FEF3C7',
    time_remaining: 'SLA Met',
    time_type: 'resolved',
    sla_status: 'RESOLVED',
    escalation_level: '—',
    icon_type: 'server',
    sla_pct: 100,
  },
];

function getRiskMeta(score) {
  if (score >= 90) return { color: '#DC2626', bg: '#FEE2E2', label: 'CRITICAL', border: '#FECACA' };
  if (score >= 80) return { color: '#EA580C', bg: '#FFEDD5', label: 'CRITICAL', border: '#FED7AA' };
  if (score >= 70) return { color: '#D97706', bg: '#FEF3C7', label: 'HIGH', border: '#FDE68A' };
  return { color: '#64748B', bg: '#F1F5F9', label: 'MEDIUM', border: '#E2E8F0' };
}

function getStatusMeta(status) {
  switch (status) {
    case 'BREACHED':
      return { color: '#DC2626', bg: '#FEF2F2', accent: '#EF4444', label: 'BREACHED', icon: AlertTriangle };
    case 'AT RISK':
    case 'AT_RISK':
      return { color: '#D97706', bg: '#FFFBEB', accent: '#F59E0B', label: 'AT RISK', icon: AlertCircle };
    case 'ON TRACK':
    case 'ON_TRACK':
      return { color: '#16A34A', bg: '#F0FDF4', accent: '#22C55E', label: 'ON TRACK', icon: ShieldCheck };
    case 'RESOLVED':
    case 'MET':
      return { color: '#2563EB', bg: '#EFF6FF', accent: '#3B82F6', label: 'RESOLVED', icon: CheckCircle2 };
    default:
      return { color: '#64748B', bg: '#F8FAFC', accent: '#94A3B8', label: status, icon: Clock };
  }
}

function getIconComp(type) {
  switch (type) {
    case 'shield': return Shield;
    case 'code': return Code;
    case 'globe': return Globe;
    case 'database': return Database;
    default: return Server;
  }
}

/* ── Radial SLA Progress Ring ── */
function SLARing({ pct, status, size = 52 }) {
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  const meta = getStatusMeta(status);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#CBD5E1" strokeWidth={6} />
      <circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none"
        stroke={meta.accent}
        strokeWidth={6}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeDashoffset={circ / 4}
        strokeLinecap="round"
      />
      <text x={size / 2} y={size / 2 + 4} textAnchor="middle" fontSize="11" fontWeight="800" fill={meta.color}>{pct}%</text>
    </svg>
  );
}

/* ── Owner Distribution Mini Row ── */
function OwnerAvatar({ initials, bg, color }) {
  return (
    <span style={{
      width: 26, height: 26, borderRadius: 6, background: bg, color: color,
      fontSize: 9.5, fontWeight: 800, display: 'inline-flex', alignItems: 'center',
      justifyContent: 'center', border: '1.5px solid rgba(255,255,255,0.6)'
    }}>{initials}</span>
  );
}

/* ── Trend Sparkline ── */
function TrendLine({ color = '#7C3AED', points = 'M0,14 C20,12 30,6 50,10 S80,4 100,2' }) {
  return (
    <svg viewBox="0 0 100 18" style={{ width: 80, height: 18 }} preserveAspectRatio="none">
      <path d={points} fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" />
      <circle cx="100" cy="2" r="2.5" fill={color} />
    </svg>
  );
}

/* ── Horizontal Bar ── */
function HBar({ pct, color, height = 8 }) {
  return (
    <div style={{ width: '100%', height, background: '#F1F5F9', borderRadius: height / 2, overflow: 'hidden' }}>
      <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: height / 2, transition: 'width 0.6s ease' }} />
    </div>
  );
}

export default function SLAMonitor() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState(DEFAULT_SLA_FINDINGS);
  const [activeView, setActiveView] = useState('overview'); // 'overview' | 'kanban' | 'team'
  const [escalatedMap, setEscalatedMap] = useState({});

  const breached = findings.filter(f => f.sla_status === 'BREACHED');
  const atRisk = findings.filter(f => f.sla_status === 'AT RISK' || f.sla_status === 'AT_RISK');
  const onTrack = findings.filter(f => f.sla_status === 'ON TRACK' || f.sla_status === 'ON_TRACK');
  const resolved = findings.filter(f => f.sla_status === 'RESOLVED' || f.sla_status === 'MET');
  const total = findings.length;

  const teamMap = useMemo(() => {
    const map = {};
    findings.forEach(f => {
      if (!map[f.owner]) map[f.owner] = { owner: f.owner, avatar: f.owner_avatar, bg: f.owner_bg, color: f.owner_color, findings: [] };
      map[f.owner].findings.push(f);
    });
    return Object.values(map);
  }, [findings]);

  const handleEscalate = (e, finding) => {
    e.stopPropagation();
    setEscalatedMap(prev => ({ ...prev, [finding.finding_id]: true }));
    setTimeout(() => navigate(`/findings/${finding.finding_id}`), 500);
  };

  return (
    <div className="slav2-root">
      {/* ══════════════════════════════════════════════════════
          HERO HEADER
          ══════════════════════════════════════════════════════ */}
      <div className="slav2-hero">
        <div className="slav2-hero-left-block">
          <div className="slav2-hero-left">
            <div className="slav2-hero-eyebrow">
              <Timer size={12} /> SLA Command Center
            </div>
            <h1 className="slav2-hero-title">Remediation SLA Monitor</h1>
            <p className="slav2-hero-sub">Track, forecast, and act on every remediation commitment before breach.</p>
          </div>

          {/* 4 Hero Metric Pills */}
          <div className="slav2-hero-metrics">
            <div className="slav2-hm-pill red" onClick={() => setActiveView('kanban')}>
              <AlertTriangle size={18} />
              <div className="slav2-hm-body">
                <span className="slav2-hm-num">{breached.length}</span>
                <span className="slav2-hm-lbl">BREACHED</span>
              </div>
              <div className="slav2-hm-trend">{breached.length > 0 ? '↑ Critical' : '—'}</div>
            </div>

            <div className="slav2-hm-pill amber" onClick={() => setActiveView('kanban')}>
              <Flame size={18} />
              <div className="slav2-hm-body">
                <span className="slav2-hm-num">{atRisk.length}</span>
                <span className="slav2-hm-lbl">AT RISK</span>
              </div>
              <div className="slav2-hm-trend">≤ 4h window</div>
            </div>

            <div className="slav2-hm-pill green">
              <ShieldCheck size={18} />
              <div className="slav2-hm-body">
                <span className="slav2-hm-num">{onTrack.length}</span>
                <span className="slav2-hm-lbl">ON TRACK</span>
              </div>
              <div className="slav2-hm-trend">Healthy</div>
            </div>

            <div className="slav2-hm-pill blue">
              <CheckCircle2 size={18} />
              <div className="slav2-hm-body">
                <span className="slav2-hm-num">{resolved.length}</span>
                <span className="slav2-hm-lbl">RESOLVED</span>
              </div>
              <div className="slav2-hm-trend">SLA Met</div>
            </div>
          </div>
        </div>

        {/* ── Top-Right Predictive Breach Widget ── */}
        <div
          className="slav2-hero-forecast-card"
          onClick={() => navigate('/findings/DEDUP-0002')}
        >
          <div className="slav2-hfc-header">
            <div className="slav2-hfc-eyebrow">
              <span className="slav2-hfc-pulse-dot" />
              <Clock size={12} color="#7C3AED" />
              <span>NEXT PREDICTED BREACH</span>
            </div>
            <span className="slav2-hfc-badge">Urgent Priority</span>
          </div>

          <div className="slav2-hfc-val-row">
            <div className="slav2-hfc-time">01h 24m</div>
            <TrendLine color="#7C3AED" points="M0,16 Q25,8 50,14 T100,4" />
          </div>

          <div className="slav2-hfc-finding-row">
            <span className="slav2-hfc-icon-shield">
              <Code size={13} color="#D97706" />
            </span>
            <div className="slav2-hfc-finding-text">
              <div className="slav2-hfc-name">Remote Code Execution</div>
              <div className="slav2-hfc-sub">Auth Service • secops (Lvl 1)</div>
            </div>
            <button className="slav2-hfc-action-btn">
              <span>Triage</span>
              <ArrowRight size={12} />
            </button>
          </div>
        </div>

      </div>

      {/* ══════════════════════════════════════════════════════
          VIEW SWITCHER TABS
          ══════════════════════════════════════════════════════ */}
      <div className="slav2-tabs">
        {[
          { id: 'overview', label: 'Analysis Overview', icon: BarChart2 },
          { id: 'kanban', label: 'Kanban Board', icon: Layers },
          { id: 'team', label: 'Team View', icon: Users },
        ].map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`slav2-tab-btn ${activeView === tab.id ? 'active' : ''}`}
              onClick={() => setActiveView(tab.id)}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ══════════════════════════════════════════════════════
          VIEW: ANALYSIS OVERVIEW (BALANCED 2-TIER LAYOUT)
          ══════════════════════════════════════════════════════ */}
      {activeView === 'overview' && (
        <div className="slav2-balanced-overview-flow">

          {/* ── Tier 1: 3 Balanced Analytics Summary Cards ── */}
          <div className="slav2-tier1-grid">

            {/* Card 1: SLA Compliance & Status Breakdown (Side-by-side Donut & Legend) */}
            <div className="slav2-card slav2-t1-card">
              <div className="slav2-card-head">
                <Activity size={16} color="#7C3AED" />
                <h3 className="slav2-card-title">SLA Compliance & Status</h3>
              </div>

              <div className="slav2-donut-horizontal-flex">
                {/* Donut Ring */}
                <div className="slav2-donut-box">
                  <svg viewBox="0 0 130 130" width="120" height="120">
                    <circle cx="65" cy="65" r="48" fill="none" stroke="#EF4444" strokeWidth="16"
                      strokeDasharray={`${(breached.length / total) * 301.6} 301.6`}
                      strokeDashoffset="75.4" />
                    <circle cx="65" cy="65" r="48" fill="none" stroke="#F97316" strokeWidth="16"
                      strokeDasharray={`${(atRisk.length / total) * 301.6} 301.6`}
                      strokeDashoffset={`${75.4 - (breached.length / total) * 301.6}`} />
                    <circle cx="65" cy="65" r="48" fill="none" stroke="#10B981" strokeWidth="16"
                      strokeDasharray={`${(onTrack.length / total) * 301.6} 301.6`}
                      strokeDashoffset={`${75.4 - ((breached.length + atRisk.length) / total) * 301.6}`} />
                    <circle cx="65" cy="65" r="48" fill="none" stroke="#3B82F6" strokeWidth="16"
                      strokeDasharray={`${(resolved.length / total) * 301.6} 301.6`}
                      strokeDashoffset={`${75.4 - ((breached.length + atRisk.length + onTrack.length) / total) * 301.6}`} />
                    {/* Center Text */}
                    <text x="65" y="58" textAnchor="middle" fontSize="22" fontWeight="900" fill="#0F172A">
                      {Math.round(((onTrack.length + resolved.length) / total) * 100)}%
                    </text>
                    <text x="65" y="74" textAnchor="middle" fontSize="9.5" fontWeight="800" fill="#64748B">COMPLIANT</text>
                  </svg>
                </div>

                {/* Side Legend List */}
                <div className="slav2-donut-side-legend">
                  {[
                    { label: 'Breached', count: breached.length, color: '#EF4444', sub: 'Needs Action' },
                    { label: 'At Risk', count: atRisk.length, color: '#F97316', sub: '≤ 4h Window' },
                    { label: 'On Track', count: onTrack.length, color: '#10B981', sub: 'Healthy' },
                    { label: 'Resolved', count: resolved.length, color: '#3B82F6', sub: 'SLA Met' },
                  ].map(l => (
                    <div key={l.label} className="slav2-side-legend-row">
                      <span className="slav2-legend-dot" style={{ background: l.color }} />
                      <div className="slav2-side-legend-text">
                        <span className="slav2-legend-lbl">{l.label}</span>
                        <span className="slav2-legend-sub">{l.sub}</span>
                      </div>
                      <span className="slav2-legend-val">{l.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Card 2: Risk Severity Breakdown */}
            <div className="slav2-card slav2-t1-card">
              <div className="slav2-card-head">
                <Target size={16} color="#DC2626" />
                <h3 className="slav2-card-title">Risk Severity Breakdown</h3>
              </div>

              <div className="slav2-risk-bars-balanced">
                {[
                  { label: 'Critical (90+)', count: findings.filter(f => f.risk_score >= 90).length, total, color: '#DC2626' },
                  { label: 'High (80–89)', count: findings.filter(f => f.risk_score >= 80 && f.risk_score < 90).length, total, color: '#EA580C' },
                  { label: 'Medium (70–79)', count: findings.filter(f => f.risk_score >= 70 && f.risk_score < 80).length, total, color: '#D97706' },
                  { label: 'Low (< 70)', count: findings.filter(f => f.risk_score < 70).length, total, color: '#16A34A' },
                ].map(item => (
                  <div key={item.label} className="slav2-rb-row">
                    <div className="slav2-rb-header">
                      <span className="slav2-rb-label">{item.label}</span>
                      <span className="slav2-rb-count" style={{ color: item.color }}>{item.count} findings</span>
                    </div>
                    <div className="slav2-rb-track">
                      <div
                        className="slav2-rb-fill"
                        style={{
                          width: `${item.total > 0 ? (item.count / item.total) * 100 : 0}%`,
                          background: item.color,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Card 3: AI SLA Intelligence & Velocity Metrics */}
            <div className="slav2-card slav2-t1-card">
              <div className="slav2-card-head">
                <Sparkles size={16} color="#7C3AED" />
                <h3 className="slav2-card-title">SLA Intelligence & Trends</h3>
              </div>

              <div className="slav2-ai-box">
                <div className="slav2-ai-icon"><Sparkles size={14} color="#7C3AED" /></div>
                <div className="slav2-ai-text">
                  <strong>Predictive Alert:</strong> 2 findings likely breach within 4h. Prioritize <em>Remote Code Execution</em> (Score 91, KEV catalog).
                </div>
              </div>

              <div className="slav2-metrics-duo">
                <div className="slav2-metric-box">
                  <TrendLine color="#16A34A" points="M0,14 C15,12 25,8 40,9 S65,4 80,3 S95,2 100,1" />
                  <div className="slav2-metric-val green">90%</div>
                  <div className="slav2-metric-lbl">SLA Compliance</div>
                  <div className="slav2-metric-trend green">↑ 12% vs last 30d</div>
                </div>
                <div className="slav2-metric-box">
                  <TrendLine color="#2563EB" points="M0,14 C15,13 30,11 45,9 S70,7 100,4" />
                  <div className="slav2-metric-val blue">2d 14h</div>
                  <div className="slav2-metric-lbl">Avg Time to Fix</div>
                  <div className="slav2-metric-trend green">↓ 18% vs last 30d</div>
                </div>
              </div>
            </div>

          </div>

          {/* ── Tier 2: Live Breach Risk Timeline (Full-Width Responsive 2-Column Action Cards) ── */}
          <div className="slav2-card slav2-timeline-tier-card">
            <div className="slav2-timeline-tier-head">
              <div className="slav2-tth-left">
                <div className="slav2-card-head">
                  <Clock size={18} color="#D97706" />
                  <h3 className="slav2-card-title">LIVE BREACH RISK TIMELINE</h3>
                  <span className="slav2-card-badge amber">Urgent Priority Stream</span>
                </div>
                <p className="slav2-card-sub">Active remediation queue ordered by deadline urgency — Next predicted breach in 01h 24m</p>
              </div>

              <button className="slav2-timeline-switch-btn" onClick={() => setActiveView('kanban')}>
                <span>View Full Kanban Board</span>
                <ArrowRight size={13} />
              </button>
            </div>

            {/* 2-Column Spacious Finding Grid */}
            <div className="slav2-timeline-cards-grid">
              {findings
                .filter(f => f.sla_status !== 'RESOLVED')
                .sort((a, b) => a.sla_pct - b.sla_pct)
                .map((item, idx) => {
                  const meta = getStatusMeta(item.sla_status);
                  const riskMeta = getRiskMeta(item.risk_score);
                  const IconComp = getIconComp(item.icon_type);
                  const isBreached = item.sla_status === 'BREACHED';
                  const isEsc = escalatedMap[item.finding_id];

                  return (
                    <div
                      key={item.finding_id}
                      className={`slav2-timeline-card-item ${isBreached ? 'breached' : 'active'}`}
                      onClick={() => navigate(`/findings/${item.finding_id}`)}
                    >
                      {/* Top Row: Rank + Icon + Title + Risk Badge */}
                      <div className="slav2-tci-top">
                        <div className="slav2-tci-left-meta">
                          <span className="slav2-tci-rank">#{idx + 1}</span>
                          <div className="slav2-tci-icon" style={{ background: riskMeta.bg, color: riskMeta.color }}>
                            <IconComp size={16} />
                          </div>
                          <div className="slav2-tci-headings">
                            <h4 className="slav2-tci-name">{item.vulnerability_name}</h4>
                            <div className="slav2-tci-sub">
                              <span>{item.asset_name}</span>
                              <span className="slav2-dot">•</span>
                              <span className="slav2-tci-mono">{item.cve_id}</span>
                            </div>
                          </div>
                        </div>

                        <span
                          className="slav2-tci-risk-tag"
                          style={{ background: riskMeta.bg, color: riskMeta.color, border: `1px solid ${riskMeta.border}` }}
                        >
                          {item.risk_score} {riskMeta.label}
                        </span>
                      </div>

                      {/* Middle Progress Row */}
                      <div className="slav2-tci-progress-row">
                        <div className="slav2-tci-bar-wrap">
                          <div className="slav2-tci-bar-labels">
                            <span className="slav2-tci-bar-lbl">Remediation SLA Progress</span>
                            <span className="slav2-tci-time" style={{ color: meta.color }}>
                              {item.time_remaining}
                            </span>
                          </div>
                          <HBar pct={Math.max(item.sla_pct, 4)} color={meta.accent} height={8} />
                        </div>
                      </div>

                      {/* Bottom Footer: Owner + Escalation + Action CTA */}
                      <div className="slav2-tci-footer">
                        <div className="slav2-tci-owner-cell">
                          <OwnerAvatar initials={item.owner_avatar} bg={item.owner_bg} color={item.owner_color} />
                          <span className="slav2-tci-owner-name">{item.owner}</span>
                          {item.escalation_level !== '—' && (
                            <span className="slav2-kc-esc-pill">{item.escalation_level}</span>
                          )}
                        </div>

                        <div className="slav2-tci-actions" onClick={e => e.stopPropagation()}>
                          {isBreached ? (
                            <button
                              className={`slav2-kc-btn escalate ${isEsc ? 'escalated' : ''}`}
                              onClick={e => handleEscalate(e, item)}
                            >
                              <span>{isEsc ? 'Escalated ✓' : 'Escalate Now'}</span>
                              <ArrowUpRight size={13} />
                            </button>
                          ) : (
                            <button
                              className="slav2-kc-btn view"
                              onClick={() => navigate(`/findings/${item.finding_id}`)}
                            >
                              <span>Inspect 360</span>
                              <ArrowRight size={13} />
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>

        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          VIEW: KANBAN BOARD (HORIZONTAL SWIMLANES & HORIZONTAL CARDS)
          ══════════════════════════════════════════════════════ */}
      {activeView === 'kanban' && (
        <div className="slav2-kanban-board-horizontal">
          {[
            { key: 'BREACHED', label: 'BREACHED', items: breached, color: '#DC2626', bg: '#FEF2F2', accent: '#EF4444', border: '#FECACA' },
            { key: 'AT RISK', label: 'AT RISK', items: atRisk, color: '#D97706', bg: '#FFFBEB', accent: '#F59E0B', border: '#FDE68A' },
            { key: 'ON TRACK', label: 'ON TRACK', items: onTrack, color: '#16A34A', bg: '#F0FDF4', accent: '#22C55E', border: '#BBF7D0' },
            { key: 'RESOLVED', label: 'RESOLVED', items: resolved, color: '#2563EB', bg: '#EFF6FF', accent: '#3B82F6', border: '#BFDBFE' },
          ].map(section => (
            <div key={section.key} className="slav2-kanban-section" style={{ borderLeft: `4px solid ${section.accent}` }}>
              {/* Horizontal Section Header */}
              <div className="slav2-kanban-section-header">
                <div className="slav2-kanban-sh-left">
                  <span className="slav2-kanban-status-badge" style={{ background: section.bg, color: section.color, border: `1px solid ${section.border}` }}>
                    {section.label}
                  </span>
                  <span className="slav2-kanban-count-pill" style={{ background: section.bg, color: section.color }}>
                    {section.items.length} {section.items.length === 1 ? 'item' : 'items'}
                  </span>
                </div>
              </div>

              {/* Horizontal Cards Grid */}
              <div className="slav2-kanban-cards-horizontal">
                {section.items.length === 0 && (
                  <div className="slav2-kanban-empty-horizontal">
                    <CheckCircle2 size={24} color="#CBD5E1" />
                    <span>No items in {section.label.toLowerCase()} status</span>
                  </div>
                )}
                {section.items.map(item => {
                  const riskMeta = getRiskMeta(item.risk_score);
                  const IconComp = getIconComp(item.icon_type);
                  const isBreached = item.sla_status === 'BREACHED';
                  const isEsc = escalatedMap[item.finding_id];

                  return (
                    <div
                      key={item.finding_id}
                      className="slav2-kanban-card horizontal"
                      onClick={() => navigate(`/findings/${item.finding_id}`)}
                    >
                      {/* Top Row: Icon + Title/Meta + Risk Badge */}
                      <div className="slav2-kc-horizontal-top">
                        <div className="slav2-kc-icon" style={{ background: riskMeta.bg, color: riskMeta.color }}>
                          <IconComp size={15} />
                        </div>
                        <div className="slav2-kc-head-info">
                          <h4 className="slav2-kc-title">{item.vulnerability_name}</h4>
                          <div className="slav2-kc-sub-info">
                            <span className="slav2-kc-asset">{item.asset_name}</span>
                            <span className="slav2-dot">•</span>
                            <span className="slav2-kc-tag mono">{item.cve_id}</span>
                            <span className="slav2-kc-tag">{item.asset_type}</span>
                          </div>
                        </div>
                        <span className="slav2-kc-risk" style={{ background: riskMeta.bg, color: riskMeta.color, border: `1px solid ${riskMeta.border}` }}>
                          {item.risk_score} {riskMeta.label}
                        </span>
                      </div>

                      {/* Bottom Row: SLA Progress Ring + Owner + CTA */}
                      <div className="slav2-kc-horizontal-bottom">
                        <div className="slav2-kc-sla-cell">
                          <SLARing pct={item.sla_pct} status={item.sla_status} size={42} />
                          <div className="slav2-kc-sla-info">
                            <span className="slav2-kc-sla-label">SLA Consumed</span>
                            <span className="slav2-kc-time" style={{ color: section.color }}>{item.time_remaining}</span>
                          </div>
                          {item.escalation_level !== '—' && (
                            <span className="slav2-kc-esc-pill">{item.escalation_level}</span>
                          )}
                        </div>

                        <div className="slav2-kc-footer-right">
                          <div className="slav2-kc-owner">
                            <OwnerAvatar initials={item.owner_avatar} bg={item.owner_bg} color={item.owner_color} />
                            <span className="slav2-kc-owner-name">{item.owner}</span>
                          </div>
                          {isBreached ? (
                            <button
                              className={`slav2-kc-btn escalate ${isEsc ? 'escalated' : ''}`}
                              onClick={e => handleEscalate(e, item)}
                            >
                              {isEsc ? '✓ Done' : 'Escalate ↑'}
                            </button>
                          ) : (
                            <button
                              className="slav2-kc-btn view"
                              onClick={e => { e.stopPropagation(); navigate(`/findings/${item.finding_id}`); }}
                            >
                              View 360 →
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          VIEW: TEAM VIEW
          ══════════════════════════════════════════════════════ */}
      {activeView === 'team' && (
        <div className="slav2-team-grid">
          {teamMap.map(team => {
            const teamBreached = team.findings.filter(f => f.sla_status === 'BREACHED').length;
            const teamAtRisk = team.findings.filter(f => f.sla_status === 'AT RISK').length;
            const teamOnTrack = team.findings.filter(f => f.sla_status === 'ON TRACK').length;
            const teamResolved = team.findings.filter(f => f.sla_status === 'RESOLVED').length;
            const topRisk = [...team.findings].sort((a, b) => b.risk_score - a.risk_score)[0];
            const health = Math.round(((teamOnTrack + teamResolved) / team.findings.length) * 100);

            return (
              <div key={team.owner} className="slav2-team-card">
                {/* Team Header */}
                <div className="slav2-tc-header">
                  <div className="slav2-tc-avatar" style={{ background: team.bg, color: team.color }}>
                    {team.avatar}
                  </div>
                  <div className="slav2-tc-name-block">
                    <div className="slav2-tc-name">{team.owner}</div>
                    <div className="slav2-tc-count">{team.findings.length} findings</div>
                  </div>
                  <div className="slav2-tc-health">
                    <div className="slav2-tc-health-num" style={{ color: health >= 80 ? '#16A34A' : health >= 50 ? '#D97706' : '#DC2626' }}>
                      {health}%
                    </div>
                    <div className="slav2-tc-health-lbl">Health</div>
                  </div>
                </div>

                {/* Status Breakdown Mini-Bars */}
                <div className="slav2-tc-status-row">
                  {teamBreached > 0 && (
                    <div className="slav2-tc-status-chip red">
                      <AlertTriangle size={10} /> {teamBreached} Breached
                    </div>
                  )}
                  {teamAtRisk > 0 && (
                    <div className="slav2-tc-status-chip amber">
                      <Flame size={10} /> {teamAtRisk} At Risk
                    </div>
                  )}
                  {teamOnTrack > 0 && (
                    <div className="slav2-tc-status-chip green">
                      <ShieldCheck size={10} /> {teamOnTrack} On Track
                    </div>
                  )}
                  {teamResolved > 0 && (
                    <div className="slav2-tc-status-chip blue">
                      <CheckCircle2 size={10} /> {teamResolved} Resolved
                    </div>
                  )}
                </div>

                {/* Stacked Horizontal Bar */}
                <div className="slav2-tc-bar-stack">
                  {teamBreached > 0 && <div style={{ flex: teamBreached, background: '#EF4444', height: '100%' }} />}
                  {teamAtRisk > 0 && <div style={{ flex: teamAtRisk, background: '#F97316', height: '100%' }} />}
                  {teamOnTrack > 0 && <div style={{ flex: teamOnTrack, background: '#10B981', height: '100%' }} />}
                  {teamResolved > 0 && <div style={{ flex: teamResolved, background: '#3B82F6', height: '100%' }} />}
                </div>

                {/* Findings List */}
                <div className="slav2-tc-findings">
                  {team.findings.map(f => {
                    const meta = getStatusMeta(f.sla_status);
                    const riskMeta = getRiskMeta(f.risk_score);
                    return (
                      <div
                        key={f.finding_id}
                        className="slav2-tc-finding-row"
                        onClick={() => navigate(`/findings/${f.finding_id}`)}
                      >
                        <div className="slav2-tc-fr-left">
                          <span className="slav2-tc-dot" style={{ background: meta.accent }} />
                          <div>
                            <div className="slav2-tc-fr-name">{f.vulnerability_name}</div>
                            <div className="slav2-tc-fr-asset">{f.asset_name}</div>
                          </div>
                        </div>
                        <div className="slav2-tc-fr-right">
                          <span className="slav2-tc-risk-badge" style={{ background: riskMeta.bg, color: riskMeta.color }}>
                            {f.risk_score}
                          </span>
                          <span className="slav2-tc-status-badge" style={{ color: meta.color }}>{f.time_remaining}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Footer CTA */}
                <button
                  className="slav2-tc-cta"
                  onClick={() => navigate('/findings')}
                >
                  <Eye size={13} /> View All {team.owner} Findings
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
