import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useDashboard } from '../hooks/useDashboard';
import { useFindings } from '../hooks/useFindings';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import {
  Globe, Shield, Flame, Layers, TrendingUp, AlertTriangle,
  Clock, User, Lock, Building, Monitor, Database, ArrowRight, Check,
  DatabaseZap, CheckCircle, Target, Zap, ChevronRight, MoreVertical,
  Activity, Radio, Server, AlertCircle
} from 'lucide-react';

/* ── Sparkline SVG Helper ────────────────────────────────────────────────── */
function Sparkline({ color = '#6366F1', id = 'spk' }) {
  return (
    <svg className="kpi-sparkline" viewBox="0 0 100 24" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path
        d="M 0 16 Q 15 12 30 18 T 60 8 T 85 14 L 100 6 L 100 24 L 0 24 Z"
        fill={`url(#grad-${id})`}
      />
      <path
        d="M 0 16 Q 15 12 30 18 T 60 8 T 85 14 L 100 6"
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}

export default function CommandCenter() {
  const navigate = useNavigate();
  const { summary, loading: sl, error: se } = useDashboard();
  const { findings, loading: fl, error: fe } = useFindings();

  if (sl || fl) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <div className="empty-state-icon">⚡</div>
        <h3>Loading Command Center…</h3>
      </div>
    );
  }

  if (se || fe) {
    return (
      <div className="empty-state" style={{ minHeight: '60vh' }}>
        <AlertTriangle size={32} color="#EF4444" />
        <h3>Error loading dashboard</h3>
        <p>{se || fe}</p>
      </div>
    );
  }

  const s = summary?.summary ?? {};
  
  // Donut data
  const donutData = [
    { name: 'Critical', value: s.critical ?? 2, color: '#EF4444', pct: '20%' },
    { name: 'High',     value: s.high     ?? 4, color: '#F97316', pct: '40%' },
    { name: 'Medium',   value: s.medium   ?? 3, color: '#EAB308', pct: '30%' },
    { name: 'Low',      value: s.low      ?? 1, color: '#10B981', pct: '10%' },
  ];

  const totalRisks = s.unique_findings ?? 10;

  // Pipeline modules
  const PIPELINE_MODULES = [
    { id: 'M1', label: 'M1 Normalization' },
    { id: 'M2', label: 'M2 Deduplication' },
    { id: 'M3', label: 'M3 Confidence' },
    { id: 'M4', label: 'M4 Threat Intel' },
    { id: 'M5', label: 'M5 Risk Scoring' },
    { id: 'M6', label: 'M6 Explainability' },
    { id: 'M7', label: 'M7 SLA Automation' },
    { id: 'M8', label: 'M8 Decision Intelligence', active: true },
  ];

  return (
    <div className="command-center-container">
      
      {/* ═════════════════════════════════════════════════════════════════════
          TOP PURPLE POP-UP HERO BOX
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="hero-purple-box">
        <div className="hero-content-flex">
          {/* Left Column: Heading, Subtitle, Buttons */}
          <div className="hero-left-col">
            <div className="hero-schema-tag">
              <Shield size={13} /> M8 Command Center · Schema v1.0
            </div>
            <h1 className="hero-main-title">
              RizIntel
            </h1>
            <p className="hero-description">
              Security Decision Intelligence correlates scanner noise, enriches risk with context,
              and surfaces what security teams should act on first.
            </p>
            <div className="hero-btn-row">
              <button
                className="hero-btn-primary"
                onClick={() => navigate('/findings')}
                id="hero-investigate-btn"
              >
                Investigate Critical Risks <ArrowRight size={14} />
              </button>
              <button
                className="hero-btn-outline"
                onClick={() => navigate('/intelligence')}
                id="hero-intelligence-btn"
              >
                View Security Intelligence
              </button>
            </div>
          </div>

          {/* Right Column: 3 Step Cards + Reduction Sparkline Card */}
          <div className="hero-right-col">
            {/* Step 1 */}
            <div className="hero-step-card">
              <div className="hero-step-top">
                <Target size={20} color="#8B5CF6" />
                <span className="hero-step-num">{s.raw_findings ?? 18}</span>
              </div>
              <div className="hero-step-title">Raw Signals</div>
              <div className="hero-step-sub">From 3 Scanners</div>
            </div>

            <div className="hero-arrow">→</div>

            {/* Step 2 */}
            <div className="hero-step-card">
              <div className="hero-step-top">
                <Shield size={20} color="#3B82F6" />
                <span className="hero-step-num">{s.unique_findings ?? 10}</span>
              </div>
              <div className="hero-step-title">Unique Risks</div>
              <div className="hero-step-sub">Correlated</div>
            </div>

            <div className="hero-arrow">→</div>

            {/* Step 3 */}
            <div className="hero-step-card">
              <div className="hero-step-top">
                <CheckCircle size={20} color="#8B5CF6" />
                <span className="hero-step-num">{s.actionable_findings ?? 9}</span>
              </div>
              <div className="hero-step-title">Actionable Findings</div>
              <div className="hero-step-sub">Prioritized</div>
            </div>

            {/* Reduction Rate Sparkline Card */}
            <div className="hero-reduction-card">
              <div>
                <div className="hero-reduction-num">
                  {((s.duplicate_reduction_rate ?? 0.444) * 100).toFixed(1)}%
                </div>
                <div className="hero-reduction-title">Duplicate Noise Eliminated</div>
              </div>
              <svg viewBox="0 0 100 28" style={{ width: '100%', height: 26, marginTop: 4 }}>
                <path d="M 0 18 Q 20 14 40 22 T 80 10 L 100 6 L 100 28 L 0 28 Z" fill="rgba(139, 92, 246, 0.15)" />
                <path d="M 0 18 Q 20 14 40 22 T 80 10 L 100 6" fill="none" stroke="#8B5CF6" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </div>
          </div>
        </div>

        <div className="hero-footer-tag">
          Turning noise into clarity. Prioritize with confidence.
        </div>
      </div>

      {/* ═════════════════════════════════════════════════════════════════════
          6 KPI METRIC CARDS ROW
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="kpi-cards-grid">
        {/* Card 1: Raw Signals */}
        <div className="kpi-card">
          <div className="kpi-card-top">
            <div className="kpi-icon" style={{ background: '#F5F3FF', color: '#7C3AED' }}><Layers size={13} /></div>
            <span className="kpi-label">RAW SIGNALS</span>
          </div>
          <div className="kpi-val">{s.raw_findings ?? 18}</div>
          <div className="kpi-sub">Total scanner signals</div>
          <Sparkline color="#6366F1" id="kpi-1" />
        </div>

        {/* Card 2: Unique Risks */}
        <div className="kpi-card">
          <div className="kpi-card-top">
            <div className="kpi-icon" style={{ background: '#EFF6FF', color: '#3B82F6' }}><Shield size={13} /></div>
            <span className="kpi-label">UNIQUE RISKS</span>
          </div>
          <div className="kpi-val">{s.unique_findings ?? 10}</div>
          <div className="kpi-sub">After deduplication</div>
          <Sparkline color="#3B82F6" id="kpi-2" />
        </div>

        {/* Card 3: Duplicates Correlated */}
        <div className="kpi-card">
          <div className="kpi-card-top">
            <div className="kpi-icon" style={{ background: '#FDF2F8', color: '#DB2777' }}><User size={13} /></div>
            <span className="kpi-label">DUPLICATES CORRELATED</span>
          </div>
          <div className="kpi-val">{s.duplicates_correlated ?? 8}</div>
          <div className="kpi-sub">Noise consolidated</div>
          <Sparkline color="#DB2777" id="kpi-3" />
        </div>

        {/* Card 4: Reduction Rate */}
        <div className="kpi-card">
          <div className="kpi-card-top">
            <div className="kpi-icon" style={{ background: '#ECFDF5', color: '#059669' }}><Zap size={13} /></div>
            <span className="kpi-label">REDUCTION RATE</span>
          </div>
          <div className="kpi-val" style={{ color: '#059669' }}>
            {((s.duplicate_reduction_rate ?? 0.444) * 100).toFixed(1)}%
          </div>
          <div className="kpi-sub">Signal noise eliminated</div>
          <Sparkline color="#10B981" id="kpi-4" />
        </div>

        {/* Card 5: Critical Risks */}
        <div className="kpi-card">
          <div className="kpi-card-top">
            <div className="kpi-icon" style={{ background: '#FEF2F2', color: '#EF4444' }}><AlertTriangle size={13} /></div>
            <span className="kpi-label">CRITICAL RISKS</span>
          </div>
          <div className="kpi-val" style={{ color: '#EF4444' }}>{s.critical ?? 2}</div>
          <div className="kpi-sub">Require immediate action</div>
          <Sparkline color="#EF4444" id="kpi-5" />
        </div>

        {/* Card 6: SLA Breached */}
        <div className="kpi-card">
          <div className="kpi-card-top">
            <div className="kpi-icon" style={{ background: '#FFF7ED', color: '#EA580C' }}><Clock size={13} /></div>
            <span className="kpi-label">SLA BREACHED</span>
          </div>
          <div className="kpi-val" style={{ color: '#EA580C' }}>{s.sla_breaches ?? 1}</div>
          <div className="kpi-sub">Remediation overdue</div>
          <Sparkline color="#F97316" id="kpi-6" />
        </div>
      </div>

      {/* ═════════════════════════════════════════════════════════════════════
          ATTENTION NOW SECTION
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="attention-section-card">
        <div className="attention-header-flex">
          <div>
            <div className="attention-section-title-wrap">
              <div className="cc-card-title" style={{ margin: 0 }}>Attention Now</div>
              <span className="attention-live-pill">
                <span className="attention-live-dot" /> LIVE QUEUE
              </span>
            </div>
            <div style={{ fontSize: 12, color: '#64748B', marginTop: 3 }}>
              Security decisions requiring immediate analyst focus — prioritized by M8 Decision Engine.
            </div>
          </div>
          <span className="cc-link-action" onClick={() => navigate('/findings')}>
            View Full Queue ({findings?.length || 10}) →
          </span>
        </div>

        <div className="attention-cards-container">
          {(findings && findings.length >= 4 ? findings.slice(0, 4) : [
            {
              finding_id: 'DEDUP-0001',
              cve_id: 'CVE-2026-1234',
              vulnerability_name: 'SQL Injection',
              asset_id: 'ASSET-PAY-001',
              asset_name: 'payments-prod-api-01',
              risk_score: 94,
              risk_level: 'CRITICAL',
              internet_exposure: true,
              workflow: { sla_status: 'ON_TRACK' },
              detail: {
                threat_intelligence: { epss_score: 0.91, kev_listed: true, exploit_available: true },
                scanner_consensus: { detected_by_count: 3, total_scanners: 3 },
                finding_confidence: { score: 0.96, classification: 'CONFIRMED' },
              }
            },
            {
              finding_id: 'DEDUP-0002',
              cve_id: 'CVE-2026-5678',
              vulnerability_name: 'Remote Code Execution',
              asset_id: 'ASSET-AUTH-002',
              asset_name: 'auth-prod-api-02',
              risk_score: 91,
              risk_level: 'CRITICAL',
              internet_exposure: true,
              workflow: { sla_status: 'AT_RISK' },
              detail: {
                threat_intelligence: { epss_score: 0.86, kev_listed: true, exploit_available: true },
                scanner_consensus: { detected_by_count: 2, total_scanners: 3 },
                finding_confidence: { score: 0.96, classification: 'CONFIRMED' },
              }
            },
            {
              finding_id: 'DEDUP-0006',
              cve_id: 'CVE-2026-9012',
              vulnerability_name: 'Authentication Bypass',
              asset_id: 'ASSET-ERP-006',
              asset_name: 'erp-prod-01',
              risk_score: 88,
              risk_level: 'HIGH',
              internet_exposure: false,
              workflow: { sla_status: 'BREACHED' },
              detail: {
                threat_intelligence: { epss_score: 0.79, kev_listed: true, exploit_available: true },
                scanner_consensus: { detected_by_count: 3, total_scanners: 3 },
                finding_confidence: { score: 0.92, classification: 'CONFIRMED' },
              }
            },
            {
              finding_id: 'DEDUP-0009',
              cve_id: 'CVE-2026-3456',
              vulnerability_name: 'Server-Side Request Forgery',
              asset_id: 'ASSET-FEE-009',
              asset_name: 'fee-api-gateway-01',
              risk_score: 84,
              risk_level: 'HIGH',
              internet_exposure: true,
              workflow: { sla_status: 'AT_RISK' },
              detail: {
                threat_intelligence: { epss_score: 0.74, kev_listed: false, exploit_available: true },
                scanner_consensus: { detected_by_count: 2, total_scanners: 3 },
                finding_confidence: { score: 0.90, classification: 'CONFIRMED' },
              }
            }
          ]).map((item, idx) => {
            const rankNum = idx + 1;
            const isCritical = item.risk_level === 'CRITICAL' || item.risk_score >= 90;
            const slaStatus = (item.workflow?.sla_status || 'ON_TRACK').toUpperCase();
            const ti = item.detail?.threat_intelligence || {};
            const sc = item.detail?.scanner_consensus || {};
            const fc = item.detail?.finding_confidence || {};
            const assetName = item.detail?.asset_context?.asset_name || item.asset_name || item.asset_id;

            return (
              <div
                key={item.finding_id || idx}
                className={`priority-card ${isCritical ? 'severity-critical' : 'severity-high'}`}
                onClick={() => navigate(`/findings/${item.finding_id}`)}
              >
                {/* Top Bar: Rank & CVE */}
                <div className="priority-card-top-bar">
                  <div className={`priority-rank-badge ${isCritical ? 'p-crit' : 'p-high'}`}>
                    <span className="priority-rank-pulse" />
                    #{String(rankNum).padStart(2, '0')} PRIORITY
                  </div>
                  {item.cve_id && (
                    <span className="priority-cve-pill">{item.cve_id}</span>
                  )}
                </div>

                {/* Vulnerability Title & Asset */}
                <div className="priority-card-title" title={item.vulnerability_name}>
                  {item.vulnerability_name}
                </div>
                <div className="priority-card-asset-row">
                  {item.internet_exposure ? <Globe size={13} color="#3B82F6" /> : <Server size={13} color="#64748B" />}
                  <span className="asset-name">{assetName}</span>
                  <span className="asset-id-dim">· {item.asset_id}</span>
                </div>

                {/* Metrics Row: Risk Score + SLA */}
                <div className="priority-metrics-box">
                  <div className="priority-score-left">
                    <div className={`priority-score-circle ${isCritical ? 'bg-crit' : 'bg-high'}`}>
                      {item.risk_score}
                    </div>
                    <div className="priority-score-meta">
                      <span className="priority-score-label">RISK SCORE</span>
                      <span className={`priority-severity-tag ${isCritical ? 'text-crit' : 'text-high'}`}>
                        {item.risk_level || (isCritical ? 'CRITICAL' : 'HIGH')}
                      </span>
                    </div>
                  </div>

                  {/* SLA Status Badge */}
                  {slaStatus.includes('BREACH') ? (
                    <span className="priority-sla-pill sla-breached">
                      <Clock size={11} /> SLA BREACHED
                    </span>
                  ) : slaStatus.includes('RISK') ? (
                    <span className="priority-sla-pill sla-at-risk">
                      <AlertTriangle size={11} /> SLA AT RISK
                    </span>
                  ) : (
                    <span className="priority-sla-pill sla-on-track">
                      <Check size={11} /> SLA ON TRACK
                    </span>
                  )}
                </div>

                {/* Structured Telemetry Intelligence Badges */}
                <div className="priority-signals-grid">
                  <div className="intel-badge-row">
                    {ti.kev_listed && (
                      <span className="intel-badge cisa-kev" title="Listed on CISA Known Exploited Vulnerabilities Catalog">
                        <Flame size={12} /> CISA KEV
                      </span>
                    )}
                    {ti.epss_score != null && (
                      <span className="intel-badge epss-high" title={`Exploit Prediction Scoring System: ${(ti.epss_score * 100).toFixed(0)}%`}>
                        <TrendingUp size={12} /> EPSS {(ti.epss_score * 100).toFixed(0)}%
                      </span>
                    )}
                    {ti.exploit_available && (
                      <span className="intel-badge exploit-ready" title="Public exploit code is available">
                        <Zap size={12} /> Exploit Ready
                      </span>
                    )}
                  </div>

                  <div className="intel-badge-row">
                    <span className="intel-badge exposure-net">
                      {item.internet_exposure ? (
                        <><Globe size={12} /> Internet-Facing</>
                      ) : (
                        <><Shield size={12} /> Internal Network</>
                      )}
                    </span>
                    {sc.detected_by_count != null && (
                      <span className="intel-badge scanners-confirmed" title={`Detected by ${sc.detected_by_count} of ${sc.total_scanners || 3} scanners`}>
                        <Layers size={12} /> {sc.detected_by_count}/{sc.total_scanners || 3} Scanners
                      </span>
                    )}
                    {fc.score != null && (
                      <span className="intel-badge confidence-high" title={`Corroborated Finding Confidence: ${(fc.score * 100).toFixed(0)}%`}>
                        <Target size={12} /> {(fc.score * 100).toFixed(0)}% Conf
                      </span>
                    )}
                  </div>
                </div>

                {/* Footer / CTA */}
                <div className="priority-footer-btns">
                  <button
                    className="btn-investigate-sleek"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(`/findings/${item.finding_id}`);
                    }}
                  >
                    <span>Investigate Finding</span>
                    <ArrowRight size={13} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Attention Footer */}
        <div className="attention-meta-bar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 12 }}>ℹ️</span>
            <span>Data reflects the latest integration from M1–M7. Priorities are driven by risk, threat intelligence, asset criticality, exposure and SLA.</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={13} />
            <span>Last updated: 20 Aug 2026 · 14:40 IST</span>
          </div>
        </div>
      </div>

      {/* ═════════════════════════════════════════════════════════════════════
          ROW 1: THREE EQUAL CARDS (Risk Distribution, SLA Health, Signals)
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="cc-grid-3">
        
        {/* CARD 1: Risk Distribution */}
        <div className="cc-card">
          <div className="cc-card-title">Risk Distribution</div>
          <div className="donut-container">
            <div className="donut-chart-wrapper">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={46}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {donutData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center-stat">
                <div className="donut-center-num">{totalRisks}</div>
                <div className="donut-center-label">Total Risks</div>
              </div>
            </div>

            <div className="donut-legend">
              {donutData.map((item) => (
                <div key={item.name} className="donut-legend-item">
                  <div className="donut-legend-left">
                    <div className="donut-dot" style={{ background: item.color }} />
                    <span>{item.name}</span>
                  </div>
                  <div className="donut-legend-val">
                    {item.value} <span className="donut-legend-pct">({item.pct})</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="cc-info-pill blue">
            <span style={{ fontSize: 13 }}>ℹ️</span>
            <span>2 risks need immediate attention.</span>
          </div>
        </div>

        {/* CARD 2: SLA Health Overview */}
        <div className="cc-card">
          <div className="cc-card-title">SLA Health Overview</div>
          <div>
            <div className="sla-health-progress-bar">
              <div className="sla-progress-seg" style={{ width: '10%', background: '#EF4444' }} />
              <div className="sla-progress-seg" style={{ width: '20%', background: '#F97316' }} />
              <div className="sla-progress-seg" style={{ width: '60%', background: '#10B981' }} />
              <div className="sla-progress-seg" style={{ width: '10%', background: '#06B6D4' }} />
            </div>

            <div className="sla-stat-boxes">
              <div className="sla-stat-box breached">
                <div className="sla-box-label">Breached</div>
                <div className="sla-box-num">1</div>
                <div className="sla-box-pct">(10%)</div>
              </div>
              <div className="sla-stat-box at-risk">
                <div className="sla-box-label">At Risk</div>
                <div className="sla-box-num">2</div>
                <div className="sla-box-pct">(20%)</div>
              </div>
              <div className="sla-stat-box on-track">
                <div className="sla-box-label">On Track</div>
                <div className="sla-box-num">6</div>
                <div className="sla-box-pct">(60%)</div>
              </div>
              <div className="sla-stat-box met">
                <div className="sla-box-label">Met</div>
                <div className="sla-box-num">1</div>
                <div className="sla-box-pct">(10%)</div>
              </div>
            </div>
          </div>

          <div className="cc-info-pill">
            <Clock size={14} color="#7C3AED" />
            <span>1 finding has breached SLA. Escalation recommended.</span>
          </div>
        </div>

        {/* CARD 3: Security Signal Overview */}
        <div className="cc-card">
          <div className="cc-card-title">Security Signal Overview</div>
          <div className="signal-list">
            <div className="signal-item">
              <div className="signal-item-left">
                <div className="signal-icon-badge blue"><Globe size={14} /></div>
                <span>Internet-facing findings</span>
              </div>
              <span className="signal-val">6</span>
            </div>
            <div className="signal-item">
              <div className="signal-item-left">
                <div className="signal-icon-badge red"><Shield size={14} /></div>
                <span>CISA KEV listed findings</span>
              </div>
              <span className="signal-val">3</span>
            </div>
            <div className="signal-item">
              <div className="signal-item-left">
                <div className="signal-icon-badge orange"><Flame size={14} /></div>
                <span>Public exploit available</span>
              </div>
              <span className="signal-val">6</span>
            </div>
            <div className="signal-item">
              <div className="signal-item-left">
                <div className="signal-icon-badge teal"><Layers size={14} /></div>
                <span>Multi-scanner confirmed</span>
              </div>
              <span className="signal-val">4</span>
            </div>
            <div className="signal-item">
              <div className="signal-item-left">
                <div className="signal-icon-badge purple"><TrendingUp size={14} /></div>
                <span>High EPSS (≥ 70%)</span>
              </div>
              <span className="signal-val">4</span>
            </div>
          </div>

          <div className="cc-info-pill blue">
            <span style={{ fontSize: 13 }}>ℹ️</span>
            <span>Insights are from the latest integrated data.</span>
          </div>
        </div>

      </div>

      {/* ═════════════════════════════════════════════════════════════════════
          ROW 2: TOP RISKY ASSETS & INTEGRATION PROVENANCE ACTIVITY
          ═════════════════════════════════════════════════════════════════════ */}
      <div className="cc-grid-middle">
        
        {/* CARD 1: Top Risky Assets (Clickable -> Asset Risk Context, No Connecting Line) */}
        <div className="cc-card">
          <div className="cc-card-header-flex">
            <div>
              <div className="cc-card-title" style={{ margin: 0 }}>Top Risky Assets</div>
              <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>
                Click any asset to view its complete Asset Risk Context & Blast Radius.
              </div>
            </div>
            <span className="cc-link-action" onClick={() => navigate('/assets')}>
              View All Assets →
            </span>
          </div>

          <div className="risky-assets-grid">
            {/* Asset 1: Payments API */}
            <div
              className="risky-asset-card-btn crit"
              onClick={() => navigate('/assets?asset=ASSET-PAY-001')}
              title="Click to view Asset Risk Context for ASSET-PAY-001"
            >
              <span className="asset-tag purple"><Globe size={10} /> Internet</span>
              <div className="asset-circle-wrapper">
                <div className="asset-circle glowing-red">
                  <Globe size={20} />
                </div>
              </div>
              <div className="asset-name" title="payments-prod-api-01">payments-prod-api-01</div>
              <div className="asset-id-label">ASSET-PAY-001</div>
              <div className="asset-score-big" style={{ color: '#DC2626' }}>94</div>
              <div className="asset-subtext">1 Critical Finding</div>
              <div className="asset-click-action">Risk Context →</div>
            </div>

            {/* Asset 2: Auth API */}
            <div
              className="risky-asset-card-btn crit"
              onClick={() => navigate('/assets?asset=ASSET-AUTH-002')}
              title="Click to view Asset Risk Context for ASSET-AUTH-002"
            >
              <span className="asset-tag purple"><Globe size={10} /> Internet</span>
              <div className="asset-circle-wrapper">
                <div className="asset-circle purple">
                  <Lock size={20} />
                </div>
              </div>
              <div className="asset-name" title="auth-prod-api-02">auth-prod-api-02</div>
              <div className="asset-id-label">ASSET-AUTH-002</div>
              <div className="asset-score-big" style={{ color: '#DC2626' }}>91</div>
              <div className="asset-subtext">1 Critical Finding</div>
              <div className="asset-click-action">Risk Context →</div>
            </div>

            {/* Asset 3: Faculty ERP */}
            <div
              className="risky-asset-card-btn high"
              onClick={() => navigate('/assets?asset=ASSET-ERP-006')}
              title="Click to view Asset Risk Context for ASSET-ERP-006"
            >
              <span className="asset-tag orange"><Server size={10} /> Internal</span>
              <div className="asset-circle-wrapper">
                <div className="asset-circle orange">
                  <Building size={20} />
                </div>
              </div>
              <div className="asset-name" title="erp-prod-01">erp-prod-01</div>
              <div className="asset-id-label">ASSET-ERP-006</div>
              <div className="asset-score-big" style={{ color: '#EA580C' }}>88</div>
              <div className="asset-subtext">2 High Findings</div>
              <div className="asset-click-action">Risk Context →</div>
            </div>

            {/* Asset 4: Student Portal */}
            <div
              className="risky-asset-card-btn high"
              onClick={() => navigate('/assets?asset=ASSET-STUDENT-003')}
              title="Click to view Asset Risk Context for ASSET-STUDENT-003"
            >
              <span className="asset-tag purple"><Globe size={10} /> Internet</span>
              <div className="asset-circle-wrapper">
                <div className="asset-circle yellow">
                  <Monitor size={20} />
                </div>
              </div>
              <div className="asset-name" title="student-portal">student-portal</div>
              <div className="asset-id-label">ASSET-STUDENT-003</div>
              <div className="asset-score-big" style={{ color: '#D97706' }}>78</div>
              <div className="asset-subtext">1 High Finding</div>
              <div className="asset-click-action">Risk Context →</div>
            </div>

            {/* Asset 5: Lab Server */}
            <div
              className="risky-asset-card-btn med"
              onClick={() => navigate('/assets?asset=ASSET-LAB-004')}
              title="Click to view Asset Risk Context for ASSET-LAB-004"
            >
              <span className="asset-tag green"><Server size={10} /> Internal</span>
              <div className="asset-circle-wrapper">
                <div className="asset-circle green">
                  <Database size={20} />
                </div>
              </div>
              <div className="asset-name" title="lab-server-01">lab-server-01</div>
              <div className="asset-id-label">ASSET-LAB-004</div>
              <div className="asset-score-big" style={{ color: '#16A34A' }}>52</div>
              <div className="asset-subtext">1 Medium Finding</div>
              <div className="asset-click-action">Risk Context →</div>
            </div>
          </div>

          <div className="risky-assets-legend">
            <div className="risky-legend-dots">
              <span style={{ fontWeight: 600, color: '#334155' }}>Risk Threshold:</span>
              <span><span className="donut-dot" style={{ background: '#EF4444', display: 'inline-block' }} /> Critical (≥90)</span>
              <span><span className="donut-dot" style={{ background: '#F97316', display: 'inline-block' }} /> High (70–89)</span>
              <span><span className="donut-dot" style={{ background: '#10B981', display: 'inline-block' }} /> Medium (&lt;70)</span>
            </div>
            <span>Click card to inspect asset landscape</span>
          </div>
        </div>

        {/* CARD 2: Integration & Provenance Activity Feed */}
        <div className="cc-card">
          <div className="cc-card-header-flex">
            <div>
              <div className="cc-card-title" style={{ margin: 0 }}>Integration & Provenance Activity</div>
              <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>
                Live decision trail from ingestion to SLA remediation.
              </div>
            </div>
            <span className="cc-link-action" onClick={() => navigate('/findings')}>
              Trace All →
            </span>
          </div>

          <div className="provenance-feed-list">
            {/* Event 1: M2 Deduplication */}
            <div
              className="provenance-activity-item"
              onClick={() => navigate('/findings/DEDUP-0001?tab=journey')}
              title="Click to trace provenance journey for DEDUP-0001"
            >
              <div className="provenance-item-left">
                <span className="provenance-mod-tag m2">M2 DEDUP</span>
                <div className="provenance-details">
                  <div className="provenance-title">Scanner Consensus: 3 Ingestions Correlated</div>
                  <div className="provenance-sub">ZAP + Nuclei + OpenVAS unified into DEDUP-0001 (SQL Injection)</div>
                </div>
              </div>
              <div className="provenance-item-right">
                <span className="provenance-time">2m ago</span>
                <span className="provenance-inspect-btn">Trace <ArrowRight size={10} /></span>
              </div>
            </div>

            {/* Event 2: M4 Threat Intelligence */}
            <div
              className="provenance-activity-item"
              onClick={() => navigate('/findings/DEDUP-0001?tab=evidence')}
              title="Click to view threat intelligence & CISA KEV evidence for CVE-2026-1234"
            >
              <div className="provenance-item-left">
                <span className="provenance-mod-tag m4">M4 INTEL</span>
                <div className="provenance-details">
                  <div className="provenance-title">CISA KEV Catalog Match & EPSS 91% Enriched</div>
                  <div className="provenance-sub">Active exploit code detected in the wild for CVE-2026-1234</div>
                </div>
              </div>
              <div className="provenance-item-right">
                <span className="provenance-time">8m ago</span>
                <span className="provenance-inspect-btn">Trace <ArrowRight size={10} /></span>
              </div>
            </div>

            {/* Event 3: M5 Dynamic Scoring */}
            <div
              className="provenance-activity-item"
              onClick={() => navigate('/findings/DEDUP-0001?tab=overview')}
              title="Click to view M5 risk calculation breakdown for DEDUP-0001"
            >
              <div className="provenance-item-left">
                <span className="provenance-mod-tag m5">M5 SCORE</span>
                <div className="provenance-details">
                  <div className="provenance-title">M5 Dynamic Risk Calculation: 94 (Critical)</div>
                  <div className="provenance-sub">Vectors: CVSS (25.5) + EPSS (18.2) + KEV (15.0) + Asset (12.0)</div>
                </div>
              </div>
              <div className="provenance-item-right">
                <span className="provenance-time">14m ago</span>
                <span className="provenance-inspect-btn">Trace <ArrowRight size={10} /></span>
              </div>
            </div>

            {/* Event 4: M7 SLA Automation */}
            <div
              className="provenance-activity-item"
              onClick={() => navigate('/findings/DEDUP-0006?tab=overview')}
              title="Click to view SLA breach & escalation details for DEDUP-0006"
            >
              <div className="provenance-item-left">
                <span className="provenance-mod-tag m7">M7 SLA</span>
                <div className="provenance-details">
                  <div className="provenance-title">SLA Breach Detected · Level-1 Auto-Escalation</div>
                  <div className="provenance-sub">DEDUP-0006 (Authentication Bypass) breached 8h remediation window</div>
                </div>
              </div>
              <div className="provenance-item-right">
                <span className="provenance-time">25m ago</span>
                <span className="provenance-inspect-btn">Trace <ArrowRight size={10} /></span>
              </div>
            </div>

            {/* Event 5: M3 Confidence Filter */}
            <div
              className="provenance-activity-item"
              onClick={() => navigate('/findings/DEDUP-0002?tab=journey')}
              title="Click to trace confidence corroboration graph for DEDUP-0002"
            >
              <div className="provenance-item-left">
                <span className="provenance-mod-tag m3">M3 CONF</span>
                <div className="provenance-details">
                  <div className="provenance-title">Confidence Validated: 96% (Confirmed)</div>
                  <div className="provenance-sub">DEDUP-0002 noise filtered via multi-scanner corroboration algorithm</div>
                </div>
              </div>
              <div className="provenance-item-right">
                <span className="provenance-time">1h ago</span>
                <span className="provenance-inspect-btn">Trace <ArrowRight size={10} /></span>
              </div>
            </div>

            {/* Event 6: M8 Human-in-the-Loop */}
            <div
              className="provenance-activity-item"
              onClick={() => navigate('/findings/DEDUP-0002?tab=decision-activity')}
              title="Click to view decision audit trail for DEDUP-0002"
            >
              <div className="provenance-item-left">
                <span className="provenance-mod-tag m8">M8 AUDIT</span>
                <div className="provenance-details">
                  <div className="provenance-title">Analyst Decision Audit Recorded</div>
                  <div className="provenance-sub">Human-in-the-Loop priority override logged to immutable audit trail</div>
                </div>
              </div>
              <div className="provenance-item-right">
                <span className="provenance-time">2h ago</span>
                <span className="provenance-inspect-btn">Trace <ArrowRight size={10} /></span>
              </div>
            </div>
          </div>
        </div>

      </div>


    </div>
  );
}


