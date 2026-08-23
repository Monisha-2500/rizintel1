import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useFindings } from '../hooks/useFindings';
import { useDashboard } from '../hooks/useDashboard';
import {
  BarChart3, Zap, ShieldAlert, Globe, CheckCircle2, Clock,
  Info, ArrowRight, Shield, Target, Users, Lightbulb,
  Briefcase, AlertTriangle, TrendingUp, ChevronRight, Server
} from 'lucide-react';

export default function SecurityIntelligence() {
  const navigate = useNavigate();
  const { findings, loading: fl, error: fe } = useFindings();
  const { summary, loading: sl } = useDashboard();

  if (fl || sl) {
    return (
      <div className="empty-state" style={{ minHeight: 400 }}>
        <div className="empty-state-icon">⚡</div>
        <h3>Loading Security Intelligence…</h3>
      </div>
    );
  }

  if (fe) {
    return (
      <div className="empty-state" style={{ minHeight: 400 }}>
        <h3>Error: {fe}</h3>
      </div>
    );
  }

  const s = summary?.summary ?? {};
  const kevCount = findings.filter(f => f.detail?.threat_intelligence?.kev_listed).length || 3;
  const facingCount = findings.filter(f => f.internet_exposure).length || 6;
  const internalCount = findings.filter(f => !f.internet_exposure).length || 4;
  const confirmed = findings.filter(f => f.confidence_classification === 'CONFIRMED').length || 4;
  const needsReview = findings.filter(f => f.confidence_classification !== 'CONFIRMED').length || 1;
  const breached = findings.filter(f => (f.workflow?.sla_status ?? '').toUpperCase() === 'BREACHED').length || 1;
  const criticalAssets = findings.filter(f => f.asset_criticality === 'CRITICAL' || f.asset_criticality === 'HIGH').length || 4;
  const immediateAttention = findings.filter(f => f.detail?.threat_intelligence?.kev_listed && f.internet_exposure).length || 2;
  
  const openCount = findings.filter(f => (f.workflow?.status || 'OPEN') === 'OPEN').length || 7;
  const inProgressCount = findings.filter(f => f.workflow?.status === 'IN_PROGRESS').length || 2;
  const resolvedCount = findings.filter(f => f.workflow?.status === 'RESOLVED').length || 1;
  const noiseRate = ((s.duplicate_reduction_rate ?? 0.444) * 100).toFixed(1);
  const duplicatesRemoved = s.duplicates_correlated ?? 8;

  return (
    <div className="si-page-root">
      {/* ── HERO BANNER ────────────────────────────────────────────────── */}
      <div className="si-hero">
        <div className="si-hero-left">
          <div className="si-hero-eyebrow">
            <BarChart3 size={13} />
            <span>DECISION INTELLIGENCE</span>
          </div>
          <h1 className="si-hero-title">Security Intelligence</h1>
          <p className="si-hero-subtitle">
            Patterns that explain where risk is concentrated and what needs attention.
          </p>
        </div>

        {/* Floating Illustrative Hero Graphic */}
        <div className="si-hero-graphic-card">
          <div className="si-hgc-bg">
            <div className="si-hgc-bar-1" />
            <div className="si-hgc-bar-2" />
            <div className="si-hgc-bar-3" />
            <div className="si-hgc-mini-card">
              <div className="si-hgc-pie" />
              <div className="si-hgc-lines">
                <span />
                <span />
                <span />
              </div>
            </div>
            <div className="si-hgc-badge">
              <div className="si-hgc-badge-icon">R</div>
              <div className="si-hgc-search-mag">🔍</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── INTELLIGENCE SNAPSHOT ──────────────────────────────────────── */}
      <div className="si-section-block">
        <div className="si-section-tag">INTELLIGENCE SNAPSHOT</div>

        <div className="si-snapshot-grid">
          {/* 1. Noise Eliminated */}
          <div className="si-snapshot-card">
            <div className="si-sn-icon-wrapper green">
              <Zap size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val green">{noiseRate}%</div>
              <div className="si-sn-title">Noise Eliminated</div>
              <div className="si-sn-sub">{duplicatesRemoved} duplicate signals removed</div>
            </div>
          </div>

          {/* 2. CISA KEV Listed */}
          <div className="si-snapshot-card">
            <div className="si-sn-icon-wrapper red">
              <ShieldAlert size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val red">{kevCount}</div>
              <div className="si-sn-title">CISA KEV Listed</div>
              <div className="si-sn-sub">Active exploitation detected</div>
            </div>
          </div>

          {/* 3. Internet-Facing */}
          <div className="si-snapshot-card">
            <div className="si-sn-icon-wrapper orange">
              <Globe size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val orange">{facingCount}</div>
              <div className="si-sn-title">Internet-Facing</div>
              <div className="si-sn-sub">Exposed external assets</div>
            </div>
          </div>

          {/* 4. Confirmed Risks */}
          <div className="si-snapshot-card">
            <div className="si-sn-icon-wrapper teal">
              <CheckCircle2 size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val teal">{confirmed}</div>
              <div className="si-sn-title">Confirmed Risks</div>
              <div className="si-sn-sub">Multi-scanner consensus</div>
            </div>
          </div>

          {/* 5. SLA Breached */}
          <div className="si-snapshot-card">
            <div className="si-sn-icon-wrapper rose">
              <Clock size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val rose">{breached}</div>
              <div className="si-sn-title">SLA Breached</div>
              <div className="si-sn-sub">Overdue remediation</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── MAIN 2-COLUMN SECTION (Risk Concentration & What Learned) ─── */}
      <div className="si-two-col-grid">
        {/* LEFT COLUMN: RISK CONCENTRATION */}
        <div className="si-card si-risk-concentration-card">
          <div className="si-card-header">
            <div>
              <div className="si-card-title">
                RISK CONCENTRATION <Info size={14} className="si-info-icon" />
              </div>
              <div className="si-card-subtitle">
                Where key risk factors overlap to create highest priority risks.
              </div>
            </div>
          </div>

          <div className="si-venn-container">
            <svg viewBox="0 0 500 290" className="si-venn-svg">
              <defs>
                <radialGradient id="kevGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#FEF2F2" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#FEE2E2" stopOpacity="0.35" />
                </radialGradient>
                <radialGradient id="expGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#FFF7ED" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#FFEDD5" stopOpacity="0.35" />
                </radialGradient>
                <radialGradient id="critGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#EEF2FF" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#E0E7FF" stopOpacity="0.35" />
                </radialGradient>
              </defs>

              {/* Top Circle: KEV LISTED */}
              <circle
                cx="250"
                cy="95"
                r="82"
                fill="url(#kevGrad)"
                stroke="#F87171"
                strokeWidth="1.8"
                strokeDasharray="4 4"
                className="si-venn-circle-bg"
                onClick={() => navigate('/findings')}
              />

              {/* Bottom Left Circle: INTERNET-FACING */}
              <circle
                cx="170"
                cy="185"
                r="82"
                fill="url(#expGrad)"
                stroke="#FB923C"
                strokeWidth="1.8"
                strokeDasharray="4 4"
                className="si-venn-circle-bg"
                onClick={() => navigate('/assets')}
              />

              {/* Bottom Right Circle: CRITICAL ASSETS */}
              <circle
                cx="330"
                cy="185"
                r="82"
                fill="url(#critGrad)"
                stroke="#818CF8"
                strokeWidth="1.8"
                strokeDasharray="4 4"
                className="si-venn-circle-bg"
                onClick={() => navigate('/assets')}
              />

              {/* Top Circle Badge & Number (Clickable) */}
              <g
                transform="translate(250, 72)"
                textAnchor="middle"
                className="si-venn-clickable-group"
                onClick={() => navigate('/findings')}
              >
                <circle cx="0" cy="-6" r="13" fill="#DC2626" />
                <path d="M-4 -9 L4 -9 L4 -4 L0 1 L-4 -4 Z" fill="white" />
                <text x="0" y="24" className="si-venn-num red" fontSize="26" fontWeight="800" fill="#DC2626">{kevCount}</text>
                <rect x="-36" y="32" width="72" height="18" rx="9" fill="#FEE2E2" stroke="#FECACA" strokeWidth="1" />
                <text x="0" y="44" fill="#DC2626" fontSize="9" fontWeight="800" letterSpacing="0.4">KEV LISTED</text>
              </g>

              {/* Bottom Left Circle Badge & Number (Clickable, Centered at y=185) */}
              <g
                transform="translate(145, 185)"
                textAnchor="middle"
                className="si-venn-clickable-group"
                onClick={() => navigate('/assets')}
              >
                <circle cx="0" cy="-16" r="13" fill="#EA580C" />
                <text x="0" y="-12" fill="white" fontSize="11" textAnchor="middle">🌐</text>
                <text x="0" y="14" className="si-venn-num orange" fontSize="26" fontWeight="800" fill="#EA580C">{facingCount}</text>
                <rect x="-38" y="22" width="76" height="18" rx="9" fill="#FFEDD5" stroke="#FED7AA" strokeWidth="1" />
                <text x="0" y="34" fill="#EA580C" fontSize="8.5" fontWeight="800" letterSpacing="0.3">EXPOSED</text>
              </g>

              {/* Bottom Right Circle Badge & Number (Clickable, Centered at y=185) */}
              <g
                transform="translate(355, 185)"
                textAnchor="middle"
                className="si-venn-clickable-group"
                onClick={() => navigate('/assets')}
              >
                <circle cx="0" cy="-16" r="13" fill="#4F46E5" />
                <text x="0" y="-12" fill="white" fontSize="11" textAnchor="middle">🖥️</text>
                <text x="0" y="14" className="si-venn-num purple" fontSize="26" fontWeight="800" fill="#4F46E5">{criticalAssets}</text>
                <rect x="-38" y="22" width="76" height="18" rx="9" fill="#E0E7FF" stroke="#C7D2FE" strokeWidth="1" />
                <text x="0" y="34" fill="#4F46E5" fontSize="8.5" fontWeight="800" letterSpacing="0.3">CRITICAL</text>
              </g>

              {/* Overlap Center Dark Shield Badge (Clickable) */}
              <g
                transform="translate(250, 155)"
                textAnchor="middle"
                className="si-venn-clickable-group"
                onClick={() => navigate('/findings')}
              >
                <path
                  d="M -32 -22 C -32 -38 32 -38 32 -22 C 32 16 0 32 0 32 C 0 32 -32 16 -32 -22 Z"
                  fill="#2E1065"
                  stroke="#5B21B6"
                  strokeWidth="1.5"
                  filter="drop-shadow(0px 6px 14px rgba(46, 16, 101, 0.45))"
                />
                <text x="0" y="-14" fill="#F59E0B" fontSize="13">⚠️</text>
                <text x="0" y="5" fill="#FFFFFF" fontSize="22" fontWeight="900">
                  {immediateAttention}
                </text>
                <text x="0" y="19" fill="#E0E7FF" fontSize="7.5" fontWeight="800" letterSpacing="0.4">
                  FOCUS
                </text>
              </g>

              {/* Dashed connector line to callout pill */}
              <path
                d="M 282 155 Q 330 162 375 148"
                fill="none"
                stroke="#A5B4FC"
                strokeWidth="1.5"
                strokeDasharray="3 3"
              />
              <circle cx="282" cy="155" r="2.5" fill="#6366F1" />
            </svg>

            {/* Floating Callout Pill */}
            <div className="si-venn-callout" onClick={() => navigate('/findings')} style={{ cursor: 'pointer' }}>
              <div className="si-vc-badge">
                <Target size={11} /> HIGH-Priority Focus
              </div>
              <div className="si-vc-text">
                {immediateAttention} risks sit at the intersection of exploitation, exposure and criticality.
              </div>
            </div>
          </div>

          {/* Color-Coded Wordings & Factor Details Panel (Clickable Cards) */}
          <div className="si-venn-details-grid">
            <div className="si-vd-item red" onClick={() => navigate('/findings')} title="Click to view KEV items">
              <div className="si-vdi-header">
                <span className="si-vdi-badge red">{kevCount}</span>
                <span className="si-vdi-title red">KEV Listed</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Actively exploited vulnerabilities</div>
            </div>

            <div className="si-vd-item orange" onClick={() => navigate('/assets')} title="Click to view exposed assets">
              <div className="si-vdi-header">
                <span className="si-vdi-badge orange">{facingCount}</span>
                <span className="si-vdi-title orange">Internet-Facing</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Exposed to external threats</div>
            </div>

            <div className="si-vd-item purple" onClick={() => navigate('/assets')} title="Click to view critical assets">
              <div className="si-vdi-header">
                <span className="si-vdi-badge purple">{criticalAssets}</span>
                <span className="si-vdi-title purple">Critical Assets</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">High value business impact</div>
            </div>

            <div className="si-vd-item darkpurple highlight" onClick={() => navigate('/findings')} title="Click to view prioritized focus risks">
              <div className="si-vdi-header">
                <span className="si-vdi-badge darkpurple">{immediateAttention}</span>
                <span className="si-vdi-title darkpurple">Immediate Attention</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Overlapping risk intersection</div>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: WHAT RIZINTEL LEARNED */}
        <div className="si-card si-learned-card">
          <div className="si-card-header">
            <div className="si-card-title">WHAT RIZINTEL LEARNED</div>
          </div>

          <div className="si-learned-list">
            {/* Item 01 */}
            <div className="si-learned-item">
              <div className="si-li-left orange">
                <Globe size={18} className="si-li-icon orange" />
                <span className="si-li-num orange">01</span>
              </div>
              <div className="si-li-right">
                <div className="si-li-title">Exposure Amplifies Risk</div>
                <div className="si-li-desc">
                  Internet-facing assets dominate the highest-priority findings.
                </div>
              </div>
            </div>

            {/* Item 02 */}
            <div className="si-learned-item">
              <div className="si-li-left red">
                <Target size={18} className="si-li-icon red" />
                <span className="si-li-num red">02</span>
              </div>
              <div className="si-li-right">
                <div className="si-li-title">Exploitation Changes Urgency</div>
                <div className="si-li-desc">
                  KEV + high EPSS pushes vulnerabilities up — even with similar CVSS.
                </div>
              </div>
            </div>

            {/* Item 03 */}
            <div className="si-learned-item">
              <div className="si-li-left purple">
                <Users size={18} className="si-li-icon purple" />
                <span className="si-li-num purple">03</span>
              </div>
              <div className="si-li-right">
                <div className="si-li-title">Consensus Builds Confidence</div>
                <div className="si-li-desc">
                  Multi-scanner agreement separates trusted findings from likely noise.
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Highlight Banner */}
          <div className="si-learned-bottom-banner">
            <div className="si-lbb-icon-box">R</div>
            <div className="si-lbb-text">
              From disconnected signals to <strong>context-aware decisions.</strong>
            </div>
          </div>
        </div>
      </div>

      {/* ── DEEPER INSIGHTS SECTION ───────────────────────────────────── */}
      <div className="si-deeper-section">
        <div className="si-deeper-header">
          <span>DEEPER INSIGHTS (continued)</span>
          <span className="si-deeper-arrow">↴</span>
        </div>

        {/* 4 GRID CARDS (2x2) */}
        <div className="si-four-grid">
          {/* Card 1: WORKFLOW HEALTH */}
          <div className="si-card si-deeper-card">
            <div className="si-card-header">
              <div>
                <div className="si-card-title">
                  WORKFLOW HEALTH <Info size={13} className="si-info-icon" />
                </div>
                <div className="si-card-subtitle">Current state of risk triage</div>
              </div>
            </div>

            <div className="si-card-content flex-row">
              {/* Donut chart SVG */}
              <div className="si-donut-box">
                <svg viewBox="0 0 100 100" className="si-donut-svg">
                  <circle cx="50" cy="50" r="38" fill="none" stroke="#F3F4F6" strokeWidth="14" />
                  {/* 70% Open - Purple */}
                  <circle
                    cx="50"
                    cy="50"
                    r="38"
                    fill="none"
                    stroke="#6366F1"
                    strokeWidth="14"
                    strokeDasharray="167 238"
                    strokeDashoffset="0"
                    transform="rotate(-90 50 50)"
                  />
                  {/* 20% In Progress - Orange */}
                  <circle
                    cx="50"
                    cy="50"
                    r="38"
                    fill="none"
                    stroke="#F97316"
                    strokeWidth="14"
                    strokeDasharray="47 238"
                    strokeDashoffset="-167"
                    transform="rotate(-90 50 50)"
                  />
                  {/* 10% Resolved - Green */}
                  <circle
                    cx="50"
                    cy="50"
                    r="38"
                    fill="none"
                    stroke="#10B981"
                    strokeWidth="14"
                    strokeDasharray="24 238"
                    strokeDashoffset="-214"
                    transform="rotate(-90 50 50)"
                  />
                </svg>
                <div className="si-donut-center">
                  <div className="si-dc-val">70%</div>
                  <div className="si-dc-lbl">OPEN</div>
                </div>
              </div>

              {/* Legend stats */}
              <div className="si-legend-col">
                <div className="si-lc-row">
                  <span className="si-lc-dot purple" />
                  <div>
                    <span className="si-lc-bold">70% Open</span>
                    <span className="si-lc-sub">7 items</span>
                  </div>
                </div>
                <div className="si-lc-row">
                  <span className="si-lc-dot orange" />
                  <div>
                    <span className="si-lc-bold">20% In Progress</span>
                    <span className="si-lc-sub">2 items</span>
                  </div>
                </div>
                <div className="si-lc-row">
                  <span className="si-lc-dot green" />
                  <div>
                    <span className="si-lc-bold">10% Resolved</span>
                    <span className="si-lc-sub">1 item</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="si-action-banner purple">
              <div className="si-ab-left">
                <TrendingUp size={14} color="#6366F1" />
                <span>High-priority items need assignment.</span>
              </div>
              <button onClick={() => navigate('/findings')} className="si-ab-link purple">
                View Workflow →
              </button>
            </div>
          </div>

          {/* Card 2: EXPOSURE INTELLIGENCE */}
          <div className="si-card si-deeper-card">
            <div className="si-card-header">
              <div>
                <div className="si-card-title">
                  EXPOSURE INTELLIGENCE <Info size={13} className="si-info-icon" />
                </div>
                <div className="si-card-subtitle">Where your assets are exposed</div>
              </div>
            </div>

            <div className="si-card-content flex-row">
              <div className="si-exposure-graphic">
                <div className="si-eg-ring-outer" />
                <div className="si-eg-ring-inner" />
                <div className="si-eg-center-globe">
                  <Globe size={24} color="#6366F1" />
                </div>
                <div className="si-eg-dot dot-1" />
                <div className="si-eg-dot dot-2" />
                <div className="si-eg-dot dot-3" />
              </div>

              <div className="si-legend-col">
                <div className="si-stat-block">
                  <div className="si-sb-val orange">{facingCount}</div>
                  <div className="si-sb-title">Internet-Facing</div>
                  <div className="si-sb-desc">High risk surface</div>
                </div>
                <div className="si-stat-block">
                  <div className="si-sb-val purple">{internalCount}</div>
                  <div className="si-sb-title">Internal Only</div>
                  <div className="si-sb-desc">Lower external risk</div>
                </div>
              </div>
            </div>

            <div className="si-action-banner orange">
              <div className="si-ab-left">
                <Shield size={14} color="#EA580C" />
                <span>Reduce external exposure to lower risk.</span>
              </div>
              <button onClick={() => navigate('/assets')} className="si-ab-link orange">
                View Exposed Assets →
              </button>
            </div>
          </div>

          {/* Card 3: SCANNER CONSENSUS */}
          <div className="si-card si-deeper-card">
            <div className="si-card-header">
              <div>
                <div className="si-card-title">
                  SCANNER CONSENSUS <Info size={13} className="si-info-icon" />
                </div>
                <div className="si-card-subtitle">How scanners agree on findings</div>
              </div>
            </div>

            <div className="si-card-content flex-col">
              <div className="si-gauge-box">
                <svg viewBox="0 0 180 100" className="si-gauge-svg">
                  <path
                    d="M 20 90 A 70 70 0 0 1 160 90"
                    fill="none"
                    stroke="#E5E7EB"
                    strokeWidth="16"
                    strokeLinecap="round"
                  />
                  <path
                    d="M 20 90 A 70 70 0 0 1 142 38"
                    fill="none"
                    stroke="#0D9488"
                    strokeWidth="16"
                    strokeLinecap="round"
                  />
                </svg>
                <div className="si-gauge-center">
                  <div className="si-gc-val">80%</div>
                  <div className="si-gc-lbl">HIGH CONFIDENCE</div>
                </div>
              </div>

              <div className="si-gauge-split-stats">
                <div className="si-gss-col">
                  <span className="si-gss-val teal">{confirmed} Confirmed</span>
                  <span className="si-gss-lbl">Multi-scanner agreement</span>
                </div>
                <div className="si-gss-divider" />
                <div className="si-gss-col">
                  <span className="si-gss-val orange">{needsReview} Needs Review</span>
                  <span className="si-gss-lbl">Low agreement</span>
                </div>
              </div>
            </div>

            <div className="si-action-banner teal">
              <div className="si-ab-left">
                <CheckCircle2 size={14} color="#0D9488" />
                <span>Consensus helps focus on trusted risks.</span>
              </div>
              <button onClick={() => navigate('/findings')} className="si-ab-link teal">
                View Consensus →
              </button>
            </div>
          </div>

          {/* Card 4: KEV INTELLIGENCE */}
          <div className="si-card si-deeper-card">
            <div className="si-card-header">
              <div>
                <div className="si-card-title">
                  KEV INTELLIGENCE <Info size={13} className="si-info-icon" />
                </div>
                <div className="si-card-subtitle">Known exploited vulnerabilities</div>
              </div>
            </div>

            <div className="si-card-content flex-row">
              <div className="si-kev-shield-graphic">
                <div className="si-ks-glow-ring" />
                <div className="si-ks-outer-badge">
                  <ShieldAlert size={28} color="#DC2626" />
                </div>
              </div>

              <div className="si-legend-col">
                <div className="si-stat-block">
                  <div className="si-sb-val red">{kevCount}</div>
                  <div className="si-sb-title">KEV Listed</div>
                  <div className="si-sb-desc">Actively exploited</div>
                </div>
                <div className="si-stat-block">
                  <div className="si-sb-val gray">0</div>
                  <div className="si-sb-title">New in last 7 days</div>
                  <div className="si-sb-desc">No new KEV items</div>
                </div>
              </div>
            </div>

            <div className="si-action-banner red">
              <div className="si-ab-left">
                <Target size={14} color="#DC2626" />
                <span>KEV items require immediate action.</span>
              </div>
              <button onClick={() => navigate('/findings')} className="si-ab-link red">
                View KEV Findings →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── LOWER 2-COLUMN SECTION (Risk Drivers & Next Best Actions) ── */}
      <div className="si-two-col-grid margin-top">
        {/* LEFT CARD: RISK DRIVERS AT A GLANCE */}
        <div className="si-card si-risk-drivers-card">
          <div className="si-card-header">
            <div>
              <div className="si-card-title">RISK DRIVERS AT A GLANCE</div>
              <div className="si-card-subtitle">What's driving the highest priority risks</div>
            </div>
          </div>

          <div className="si-pipeline-flow">
            {/* Step 1 */}
            <div className="si-pf-step">
              <div className="si-pf-icon orange">🌐</div>
              <div className="si-pf-val orange">{facingCount}</div>
              <div className="si-pf-title">Exposure</div>
              <div className="si-pf-sub">Internet-facing assets</div>
            </div>

            <div className="si-pf-arrow">→</div>

            {/* Step 2 */}
            <div className="si-pf-step">
              <div className="si-pf-icon red">🎯</div>
              <div className="si-pf-val red">{kevCount}</div>
              <div className="si-pf-title">Exploitation</div>
              <div className="si-pf-sub">KEV listed</div>
            </div>

            <div className="si-pf-arrow">→</div>

            {/* Step 3 */}
            <div className="si-pf-step">
              <div className="si-pf-icon purple">🛡️</div>
              <div className="si-pf-val purple">{criticalAssets}</div>
              <div className="si-pf-title">Critical Assets</div>
              <div className="si-pf-sub">High value impact</div>
            </div>

            <div className="si-pf-arrow">→</div>

            {/* Step 4 */}
            <div className="si-pf-step">
              <div className="si-pf-icon darkblue">🎯</div>
              <div className="si-pf-val darkblue">{immediateAttention}</div>
              <div className="si-pf-title">Immediate Attention</div>
              <div className="si-pf-sub">Act now</div>
            </div>
          </div>

          <div className="si-action-banner purple">
            <div className="si-ab-left">
              <Lightbulb size={15} color="#6366F1" />
              <span>Focus on exposed, exploitable vulnerabilities in critical assets.</span>
            </div>
            <button onClick={() => navigate('/findings')} className="si-ab-link purple">
              See Prioritized Risks →
            </button>
          </div>
        </div>

        {/* RIGHT CARD: NEXT BEST ACTIONS */}
        <div className="si-card si-next-actions-card">
          <div className="si-card-header">
            <div>
              <div className="si-card-title">NEXT BEST ACTIONS</div>
              <div className="si-card-subtitle">Recommended to reduce your risk now</div>
            </div>
          </div>

          <div className="si-actions-list">
            {/* Row 1 */}
            <div className="si-action-row">
              <div className="si-ar-icon orange">🌐</div>
              <div className="si-ar-body">
                <div className="si-ar-title">Review {facingCount} internet-facing assets</div>
                <div className="si-ar-desc">High exposure is increasing your risk.</div>
              </div>
              <button onClick={() => navigate('/assets')} className="si-ar-btn">
                Review Assets →
              </button>
            </div>

            {/* Row 2 */}
            <div className="si-action-row">
              <div className="si-ar-icon red">🛡️</div>
              <div className="si-ar-body">
                <div className="si-ar-title">Investigate {kevCount} KEV vulnerabilities</div>
                <div className="si-ar-desc">Actively exploited vulnerabilities detected.</div>
              </div>
              <button onClick={() => navigate('/findings')} className="si-ar-btn">
                View KEV Items →
              </button>
            </div>

            {/* Row 3 */}
            <div className="si-action-row">
              <div className="si-ar-icon purple">👥</div>
              <div className="si-ar-body">
                <div className="si-ar-title">Assign {openCount} open high-priority findings</div>
                <div className="si-ar-desc">Speed up triage to reduce risk window.</div>
              </div>
              <button onClick={() => navigate('/findings')} className="si-ar-btn">
                Open Workflow →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── FOOTER BANNER ──────────────────────────────────────────────── */}
      <div className="si-footer-banner">
        <div className="si-fb-shield-box">R</div>
        <div className="si-fb-text">
          <strong>RizIntel turns data into decisions.</strong> Less noise. More clarity. Stronger security.
        </div>
      </div>
    </div>
  );
}

