import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  BarChart3, Zap, ShieldAlert, Globe, CheckCircle2, Clock,
  Info, ArrowRight, Shield, Target, Users, Lightbulb,
  AlertTriangle, TrendingUp, RefreshCw, Layers, ExternalLink,
  ChevronRight, Lock, Eye, Activity
} from 'lucide-react';
import { getFindings, getCurrentUser } from '../services/findingsService';
import { getRemediationTasks, getBreachWarnings } from '../services/slaService';
import { getAssets } from '../services/assetsService';
import { normalizeSecurityIntelligence } from '../utils/intelligenceNormalizer';

export default function SecurityIntelligence() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const orgId = searchParams.get('org_id') || 'ORG-RIZZOLVE-DEMO';
  const scanRunId = searchParams.get('scan_run_id') || null;

  const currentUser = useMemo(() => getCurrentUser(), []);
  const isViewer = currentUser?.role === 'VIEWER';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const [rawFindings, setRawFindings] = useState([]);
  const [rawTasks, setRawTasks] = useState([]);
  const [rawAssets, setRawAssets] = useState([]);
  const [breachWarnings, setBreachWarnings] = useState({ hard_breaches: [], predictive_warnings: [] });

  // Authoritative Data Fetcher
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [findingsRes, tasksRes, assetsRes, warningsRes] = await Promise.allSettled([
        getFindings({ organization_id: orgId, scan_run_id: scanRunId }),
        getRemediationTasks({ organization_id: orgId }),
        getAssets({ organization_id: orgId }),
        getBreachWarnings()
      ]);

      let loadedFindings = [];
      if (findingsRes.status === 'fulfilled') {
        const val = findingsRes.value;
        loadedFindings = Array.isArray(val) ? val : (val?.findings || []);
      }

      let loadedTasks = [];
      if (tasksRes.status === 'fulfilled' && Array.isArray(tasksRes.value)) {
        loadedTasks = tasksRes.value;
      }

      let loadedAssets = [];
      if (assetsRes.status === 'fulfilled' && Array.isArray(assetsRes.value)) {
        loadedAssets = assetsRes.value;
      }

      let loadedWarnings = { hard_breaches: [], predictive_warnings: [] };
      if (warningsRes.status === 'fulfilled' && warningsRes.value) {
        loadedWarnings = warningsRes.value;
      }

      setRawFindings(loadedFindings);
      setRawTasks(loadedTasks);
      setRawAssets(loadedAssets);
      setBreachWarnings(loadedWarnings);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Failed to load Security Intelligence data:', err);
      setError('RizIntel couldn’t retrieve the authorized analytics data right now.');
    } finally {
      setLoading(false);
    }
  }, [orgId, scanRunId]);

  useEffect(() => {
    loadData();
    window.addEventListener('rizintel-datamode-change', loadData);
    return () => {
      window.removeEventListener('rizintel-datamode-change', loadData);
    };
  }, [loadData]);

  // Normalized Authoritative Model
  const intelligence = useMemo(() => {
    return normalizeSecurityIntelligence({
      findings: rawFindings,
      tasks: rawTasks,
      assets: rawAssets,
      breachWarnings,
      orgId
    });
  }, [rawFindings, rawTasks, rawAssets, breachWarnings, orgId]);

  const { snapshot, riskDistribution, assetCriticalityDistribution, exposureDistribution, confidenceDistribution, workflowDistribution, kevIntelligence, intersections, currentInsights, nextBestActions, populations } = intelligence;

  // Percentage Calculations strictly based on declared population
  const totalF = populations.totalFindings;
  const pendingReviewWfPct = totalF > 0 ? Math.round((workflowDistribution.pendingReview / totalF) * 100) : 0;
  const openWfPct = totalF > 0 ? Math.round((workflowDistribution.open / totalF) * 100) : 0;
  const inProgressWfPct = totalF > 0 ? Math.round((workflowDistribution.inProgress / totalF) * 100) : 0;
  const resolvedWfPct = totalF > 0 ? Math.round((workflowDistribution.resolved / totalF) * 100) : 0;

  // Safe Navigation Helper preserving Scope
  const navigateWithScope = (path) => {
    const params = new URLSearchParams();
    if (orgId) params.set('organization_id', orgId);
    if (scanRunId) params.set('scan_run_id', scanRunId);
    const hasQuery = path.includes('?');
    const fullPath = `${path}${hasQuery ? '&' : '?'}${params.toString()}`;
    navigate(fullPath);
  };

  // Loading State with Skeletons
  if (loading && rawFindings.length === 0) {
    return (
      <div className="si-page-root fade-in">
        <div className="si-hero skeleton-box" style={{ height: 110 }} />
        <div className="si-snapshot-grid">
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} className="si-snapshot-card skeleton-box" style={{ height: 92 }} />
          ))}
        </div>
        <div className="si-two-col-grid">
          <div className="si-card skeleton-box" style={{ height: 320 }} />
          <div className="si-card skeleton-box" style={{ height: 320 }} />
        </div>
      </div>
    );
  }

  // Error State with Retry
  if (error && rawFindings.length === 0) {
    return (
      <div className="si-page-root fade-in">
        <div className="si-card" style={{ padding: '60px 24px', textAlign: 'center' }}>
          <AlertTriangle size={48} color="#DC2626" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary, #0F172A)', margin: '0 0 8px' }}>
            Unable to load security intelligence
          </h2>
          <p style={{ fontSize: 14, color: 'var(--text-secondary, #64748B)', maxWidth: 440, margin: '0 auto 20px' }}>
            {error}
          </p>
          <button
            onClick={loadData}
            style={{
              padding: '9px 20px',
              borderRadius: 8,
              background: '#7C3AED',
              color: '#FFFFFF',
              border: 'none',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Empty State
  if (!loading && rawFindings.length === 0) {
    return (
      <div className="si-page-root fade-in">
        <div className="si-card" style={{ padding: '60px 24px', textAlign: 'center' }}>
          <Shield size={48} color="#7C3AED" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary, #0F172A)', margin: '0 0 8px' }}>
            No security intelligence yet
          </h2>
          <p style={{ fontSize: 14, color: 'var(--text-secondary, #64748B)', maxWidth: 440, margin: '0 auto 20px' }}>
            Completed security scans will produce intelligence after findings are analyzed.
          </p>
          {!isViewer && (
            <button
              onClick={() => navigateWithScope('/scan-runs')}
              style={{
                padding: '9px 20px',
                borderRadius: 8,
                background: '#7C3AED',
                color: '#FFFFFF',
                border: 'none',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Go to Scan Runs
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="si-page-root fade-in">
      {/* ── 1. HERO BANNER ──────────────────────────────────────────────── */}
      <div className="si-hero">
        <div className="si-hero-left">
          <div className="si-hero-eyebrow">
            <BarChart3 size={13} />
            <span>SECURITY ANALYTICS</span>
            <span style={{ opacity: 0.4, margin: '0 4px' }}>/</span>
            <span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: 11 }}>{orgId}</span>
          </div>
          <h1 className="si-hero-title">Security Intelligence</h1>
          <p className="si-hero-subtitle">
            Understand where risk is concentrated and what requires attention.
          </p>
        </div>

        <div className="si-hero-actions" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ fontSize: 12, color: 'var(--text-muted, #94A3B8)', textAlign: 'right' }}>
            <span>Refreshed: {lastRefreshed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>
          <button
            onClick={loadData}
            disabled={loading}
            aria-label="Refresh Security Intelligence"
            className="si-refresh-btn"
            style={{
              padding: '8px 12px',
              borderRadius: 8,
              border: '1px solid var(--border, #E2E8F0)',
              background: 'var(--surface, #FFFFFF)',
              color: 'var(--text-primary, #0F172A)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 12.5,
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ── 2. INTELLIGENCE SNAPSHOT (5 PRIMARY CARDS) ──────────────────── */}
      <div className="si-section-block">
        <div className="si-section-tag">INTELLIGENCE SNAPSHOT</div>

        <div className="si-snapshot-grid">
          {/* Card 1: Active Findings */}
          <div
            className="si-snapshot-card clickable"
            onClick={() => navigateWithScope('/findings')}
            title={`Across ${snapshot.activeFindings} active canonical findings`}
            role="button"
            tabIndex={0}
          >
            <div className="si-sn-icon-wrapper green">
              <Layers size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val green">{snapshot.activeFindings}</div>
              <div className="si-sn-title">Active Findings</div>
              <div className="si-sn-sub">Across {snapshot.activeFindings} canonical risks</div>
            </div>
          </div>

          {/* Card 2: CISA KEV Listed */}
          <div
            className="si-snapshot-card clickable"
            onClick={() => navigateWithScope('/findings?kev=true')}
            title="Vulnerabilities present in CISA Known Exploited Vulnerabilities catalog"
            role="button"
            tabIndex={0}
          >
            <div className="si-sn-icon-wrapper red">
              <ShieldAlert size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val red">{snapshot.kevCount}</div>
              <div className="si-sn-title">CISA KEV Listed</div>
              <div className="si-sn-sub">Known exploited vulnerabilities</div>
            </div>
          </div>

          {/* Card 3: Internet-Facing */}
          <div
            className="si-snapshot-card clickable"
            onClick={() => navigateWithScope('/assets')}
            title={`Across ${snapshot.exposedFindingsCount} findings on ${snapshot.distinctExposedAssetCount} internet-facing asset${snapshot.distinctExposedAssetCount === 1 ? '' : 's'}`}
            role="button"
            tabIndex={0}
          >
            <div className="si-sn-icon-wrapper orange">
              <Globe size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val orange">{snapshot.exposedFindingsCount}</div>
              <div className="si-sn-title">Internet-Facing</div>
              <div className="si-sn-sub">{snapshot.distinctExposedAssetCount} exposed asset{snapshot.distinctExposedAssetCount === 1 ? '' : 's'}</div>
            </div>
          </div>

          {/* Card 4: Needs Review */}
          <div
            className="si-snapshot-card clickable"
            onClick={() => navigateWithScope('/findings?confidence=NEEDS_REVIEW')}
            title={`Across ${snapshot.needsReviewCount} findings requiring analyst verification`}
            role="button"
            tabIndex={0}
          >
            <div className="si-sn-icon-wrapper teal">
              <CheckCircle2 size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val teal">{snapshot.needsReviewCount}</div>
              <div className="si-sn-title">Needs Review</div>
              <div className="si-sn-sub">Awaiting analyst triage</div>
            </div>
          </div>

          {/* Card 5: SLA Breached (Reconciled with SLA Monitor) */}
          <div
            className="si-snapshot-card clickable"
            onClick={() => navigateWithScope('/sla?view=queue')}
            title="Across active remediation tasks — strictly reconciled with SLA Monitor"
            role="button"
            tabIndex={0}
          >
            <div className="si-sn-icon-wrapper rose">
              <Clock size={18} />
            </div>
            <div className="si-sn-body">
              <div className="si-sn-val rose">{snapshot.breachedCount}</div>
              <div className="si-sn-title">SLA Breached</div>
              <div className="si-sn-sub">Reconciled with SLA Monitor</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── 3. RISK CONCENTRATION & DATA-DERIVED INSIGHTS ───────────────── */}
      <div className="si-two-col-grid">
        {/* LEFT COLUMN: RISK CONCENTRATION */}
        <div className="si-card si-risk-concentration-card">
          <div className="si-card-header">
            <div>
              <div className="si-card-title">
                RISK CONCENTRATION <Info size={14} className="si-info-icon" />
              </div>
              <div className="si-card-subtitle">
                Where threat vectors overlap to form the highest priority perimeter risks.
              </div>
            </div>
          </div>

          {/* True Set Intersection Breakdown */}
          <div className="si-venn-details-grid" style={{ marginTop: 12 }}>
            <div className="si-vd-item red" onClick={() => navigateWithScope('/findings?kev=true')} title="View KEV items" role="button" tabIndex={0}>
              <div className="si-vdi-header">
                <span className="si-vdi-badge red">{intersections.kevCount}</span>
                <span className="si-vdi-title red">KEV Listed</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Known exploited vulnerability catalog</div>
            </div>

            <div className="si-vd-item orange" onClick={() => navigateWithScope('/assets')} title="View exposed assets" role="button" tabIndex={0}>
              <div className="si-vdi-header">
                <span className="si-vdi-badge orange">{intersections.exposedCount}</span>
                <span className="si-vdi-title orange">Internet-Facing</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Exposed external perimeter findings</div>
            </div>

            <div className="si-vd-item purple" onClick={() => navigateWithScope('/assets')} title="View high-criticality assets" role="button" tabIndex={0}>
              <div className="si-vdi-header">
                <span className="si-vdi-badge purple">{intersections.highCriticalityAssetFindingCount}</span>
                <span className="si-vdi-title purple">High-Criticality Assets</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Findings on high business impact assets</div>
            </div>

            <div className="si-vd-item darkpurple highlight" onClick={() => navigateWithScope('/findings?kev=true')} title="View KEV and exposed findings" role="button" tabIndex={0}>
              <div className="si-vdi-header">
                <span className="si-vdi-badge darkpurple">{intersections.kevExposedCount}</span>
                <span className="si-vdi-title darkpurple">KEV + Internet-Facing</span>
                <span className="si-vdi-arrow">→</span>
              </div>
              <div className="si-vdi-desc">Findings present in both CISA KEV and internet-facing sets</div>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: WHAT RIZINTEL LEARNED */}
        <div className="si-card si-learned-card">
          <div className="si-card-header">
            <div className="si-card-title">WHAT RIZINTEL LEARNED</div>
            <div className="si-card-subtitle">Empirical findings from the current authorized dataset</div>
          </div>

          <div className="si-learned-list">
            {currentInsights.map((insight, idx) => (
              <div key={insight.id || idx} className="si-learned-item">
                <div className={`si-li-left ${insight.color}`}>
                  <span className={`si-li-num ${insight.color}`}>0{idx + 1}</span>
                </div>
                <div className="si-li-right">
                  <div className="si-li-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>{insight.title}</span>
                    <span className={`sla-tag ${insight.color === 'red' ? 'critical' : (insight.color === 'orange' ? 'high' : 'medium')}`} style={{ fontSize: 10 }}>
                      {insight.tag}
                    </span>
                  </div>
                  <div className="si-li-desc">{insight.description}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Bottom Highlight Banner */}
          <div className="si-learned-bottom-banner">
            <div className="si-lbb-icon-box">R</div>
            <div className="si-lbb-text">
              From disconnected signals to <strong>context-aware security decisions.</strong>
            </div>
          </div>
        </div>
      </div>

      {/* ── 4. OPERATIONAL INTELLIGENCE (2x2 GRID) ─────────────────────── */}
      <div className="si-deeper-section">
        <div className="si-deeper-header">
          <span>OPERATIONAL INTELLIGENCE</span>
          <span className="si-deeper-arrow">↴</span>
        </div>

        <div className="si-four-grid">
          {/* Card 1: WORKFLOW HEALTH (Reconciled across all findings) */}
          <div className="si-card si-deeper-card">
            <div className="si-card-header">
              <div>
                <div className="si-card-title">
                  WORKFLOW HEALTH <Info size={13} className="si-info-icon" />
                </div>
                <div className="si-card-subtitle">Current state of risk triage across {totalF} canonical findings</div>
              </div>
            </div>

            <div className="si-card-content flex-col" style={{ gap: 14 }}>
              {totalF === 0 ? (
                <div style={{ color: 'var(--text-muted, #94A3B8)', fontSize: 13 }}>No eligible data</div>
              ) : (
                <>
                  <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', background: 'var(--border, #E2E8F0)', width: '100%' }}>
                    {pendingReviewWfPct > 0 && <div style={{ width: `${pendingReviewWfPct}%`, background: '#8B5CF6' }} title={`Pending Review: ${pendingReviewWfPct}%`} />}
                    {openWfPct > 0 && <div style={{ width: `${openWfPct}%`, background: '#6366F1' }} title={`Open: ${openWfPct}%`} />}
                    {inProgressWfPct > 0 && <div style={{ width: `${inProgressWfPct}%`, background: '#F97316' }} title={`In Progress: ${inProgressWfPct}%`} />}
                    {resolvedWfPct > 0 && <div style={{ width: `${resolvedWfPct}%`, background: '#10B981' }} title={`Resolved: ${resolvedWfPct}%`} />}
                  </div>

                  <div className="si-legend-col" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, width: '100%' }}>
                    <div className="si-lc-row">
                      <span className="si-lc-dot purple" style={{ background: '#8B5CF6' }} />
                      <div>
                        <span className="si-lc-bold">{pendingReviewWfPct}% Pending Review</span>
                        <span className="si-lc-sub">{workflowDistribution.pendingReview} items</span>
                      </div>
                    </div>
                    <div className="si-lc-row">
                      <span className="si-lc-dot purple" />
                      <div>
                        <span className="si-lc-bold">{openWfPct}% Open</span>
                        <span className="si-lc-sub">{workflowDistribution.open} items</span>
                      </div>
                    </div>
                    <div className="si-lc-row">
                      <span className="si-lc-dot orange" />
                      <div>
                        <span className="si-lc-bold">{inProgressWfPct}% In Progress</span>
                        <span className="si-lc-sub">{workflowDistribution.inProgress} items</span>
                      </div>
                    </div>
                    <div className="si-lc-row">
                      <span className="si-lc-dot green" />
                      <div>
                        <span className="si-lc-bold">{resolvedWfPct}% Resolved</span>
                        <span className="si-lc-sub">{workflowDistribution.resolved} item{workflowDistribution.resolved === 1 ? '' : 's'}</span>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>

            <div className="si-action-banner purple">
              <div className="si-ab-left">
                <TrendingUp size={14} color="#6366F1" />
                <span>{workflowDistribution.unassignedEligibleCount} open findings awaiting remediation assignment.</span>
              </div>
              <button onClick={() => navigateWithScope('/sla?view=team')} className="si-ab-link purple">
                {isViewer ? 'View SLA Monitor →' : 'Open SLA Monitor →'}
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
                <div className="si-card-subtitle">Perimeter attack surface breakdown</div>
              </div>
            </div>

            <div className="si-card-content flex-row">
              <div className="si-exposure-graphic">
                <div className="si-eg-ring-outer" />
                <div className="si-eg-ring-inner" />
                <div className="si-eg-center-globe">
                  <Globe size={24} color="#6366F1" />
                </div>
              </div>

              <div className="si-legend-col">
                <div className="si-stat-block">
                  <div className="si-sb-val orange">{exposureDistribution.exposedCount}</div>
                  <div className="si-sb-title">Internet-Facing</div>
                  <div className="si-sb-desc">{exposureDistribution.distinctExposedAssets} distinct asset{exposureDistribution.distinctExposedAssets === 1 ? '' : 's'}</div>
                </div>
                <div className="si-stat-block">
                  <div className="si-sb-val purple">{exposureDistribution.internalCount}</div>
                  <div className="si-sb-title">Internal Perimeter</div>
                  <div className="si-sb-desc">{exposureDistribution.internalCount} internal risks</div>
                </div>
              </div>
            </div>

            <div className="si-action-banner orange">
              <div className="si-ab-left">
                <Shield size={14} color="#EA580C" />
                <span>External exposure drives highest priority triage.</span>
              </div>
              <button onClick={() => navigateWithScope('/assets')} className="si-ab-link orange">
                {isViewer ? 'View Assets →' : 'View Exposed Assets →'}
              </button>
            </div>
          </div>

          {/* Card 3: SCANNER CONSENSUS & VALIDATION */}
          <div className="si-card si-deeper-card">
            <div className="si-card-header">
              <div>
                <div className="si-card-title">
                  SCANNER CONSENSUS & VALIDATION <Info size={13} className="si-info-icon" />
                </div>
                <div className="si-card-subtitle">Confidence classification, detection coverage & validation</div>
              </div>
            </div>

            <div className="si-card-content flex-col" style={{ gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', background: 'var(--surface-muted, #F8FAFC)', borderRadius: 8, width: '100%' }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary, #0F172A)' }}>Confidence</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted, #94A3B8)' }}>M5 Classification</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#0D9488' }}>{confidenceDistribution.highConfidence} High Confidence</span>
                  <span style={{ margin: '0 4px', color: 'var(--text-muted, #94A3B8)' }}>·</span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#EA580C' }}>{confidenceDistribution.needsReview} Needs Review</span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', background: 'var(--surface-muted, #F8FAFC)', borderRadius: 8, width: '100%' }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary, #0F172A)' }}>Detection Coverage</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted, #94A3B8)' }}>Scanner agreement</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary, #0F172A)' }}>{confidenceDistribution.singleSourceCount} Single-Source</span>
                  <span style={{ margin: '0 4px', color: 'var(--text-muted, #94A3B8)' }}>·</span>
                  <span style={{ fontSize: 12, color: 'var(--text-muted, #94A3B8)' }}>{confidenceDistribution.multiScannerCount} Multi-Scanner</span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', background: 'var(--surface-muted, #F8FAFC)', borderRadius: 8, width: '100%' }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary, #0F172A)' }}>Analyst Validation</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted, #94A3B8)' }}>Audit decisions</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#6366F1' }}>{confidenceDistribution.analystConfirmed} Confirmed</span>
                  <span style={{ margin: '0 4px', color: 'var(--text-muted, #94A3B8)' }}>·</span>
                  <span style={{ fontSize: 12, color: 'var(--text-muted, #94A3B8)' }}>{confidenceDistribution.pendingAnalystReview} Pending</span>
                </div>
              </div>
            </div>

            <div className="si-action-banner teal">
              <div className="si-ab-left">
                <CheckCircle2 size={14} color="#0D9488" />
                <span>Multi-scanner consensus isolates trusted findings.</span>
              </div>
              <button onClick={() => navigateWithScope('/findings')} className="si-ab-link teal">
                {isViewer ? 'Inspect Findings →' : 'View Consensus →'}
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
                <div className="si-card-subtitle">Known exploited vulnerability catalog tracking</div>
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
                  <div className="si-sb-val red">{kevIntelligence.kevCount}</div>
                  <div className="si-sb-title">CISA KEV Listed</div>
                  <div className="si-sb-desc">{kevIntelligence.cves.join(', ') || 'Known exploit catalog'}</div>
                </div>
                <div className="si-stat-block">
                  <div className="si-sb-val purple">{kevIntelligence.exploitAvailableCount}</div>
                  <div className="si-sb-title">Public Exploits</div>
                  <div className="si-sb-desc">{kevIntelligence.publicExploitStatusText}</div>
                </div>
              </div>
            </div>

            <div className="si-action-banner red">
              <div className="si-ab-left">
                <Target size={14} color="#DC2626" />
                <span>KEV vulnerabilities require immediate triage.</span>
              </div>
              <button onClick={() => navigateWithScope('/findings?kev=true')} className="si-ab-link red">
                {isViewer ? 'Inspect KEV →' : 'View KEV Findings →'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── 5. LOWER SECTION: RISK DRIVERS & NEXT BEST ACTIONS ─────────── */}
      <div className="si-two-col-grid margin-top">
        {/* LEFT CARD: RISK DRIVERS AT A GLANCE */}
        <div className="si-card si-risk-drivers-card">
          <div className="si-card-header">
            <div>
              <div className="si-card-title">RISK DRIVERS AT A GLANCE</div>
              <div className="si-card-subtitle">Key factors shaping contextual priority across the organization</div>
            </div>
          </div>

          <div className="si-pipeline-flow">
            <div className="si-pf-step">
              <div className="si-pf-icon orange">🌐</div>
              <div className="si-pf-val orange">{exposureDistribution.exposedCount}</div>
              <div className="si-pf-title">Exposure</div>
              <div className="si-pf-sub">Internet-facing</div>
            </div>

            <div className="si-pf-arrow">→</div>

            <div className="si-pf-step">
              <div className="si-pf-icon red">🎯</div>
              <div className="si-pf-val red">{kevIntelligence.kevCount}</div>
              <div className="si-pf-title">Exploitation</div>
              <div className="si-pf-sub">CISA KEV listed</div>
            </div>

            <div className="si-pf-arrow">→</div>

            <div className="si-pf-step">
              <div className="si-pf-icon purple">🛡️</div>
              <div className="si-pf-val purple">{intersections.highCriticalityAssetFindingCount}</div>
              <div className="si-pf-title">Asset Criticality</div>
              <div className="si-pf-sub">High impact context</div>
            </div>

            <div className="si-pf-arrow">→</div>

            <div className="si-pf-step">
              <div className="si-pf-icon darkblue">🎯</div>
              <div className="si-pf-val darkblue">{intersections.kevExposedCount}</div>
              <div className="si-pf-title">KEV + Exposed</div>
              <div className="si-pf-sub">Threat intersection</div>
            </div>
          </div>

          <div className="si-action-banner purple">
            <div className="si-ab-left">
              <Lightbulb size={15} color="#6366F1" />
              <span>Contextual risk prioritizes exploitability on exposed assets.</span>
            </div>
            <button onClick={() => navigateWithScope('/findings')} className="si-ab-link purple">
              See Prioritized Risks →
            </button>
          </div>
        </div>

        {/* RIGHT CARD: NEXT BEST ACTIONS */}
        <div className="si-card si-next-actions-card">
          <div className="si-card-header">
            <div>
              <div className="si-card-title">NEXT BEST ACTIONS</div>
              <div className="si-card-subtitle">Operational recommendations based on current dataset</div>
            </div>
          </div>

          <div className="si-actions-list">
            {nextBestActions.map((action, idx) => (
              <div key={action.id || idx} className="si-action-row">
                <div className={`si-ar-icon ${action.color}`}>{action.icon}</div>
                <div className="si-ar-body">
                  <div className="si-ar-title">{action.title}</div>
                  <div className="si-ar-desc">{action.description}</div>
                </div>
                <button onClick={() => navigateWithScope(action.path)} className="si-ar-btn">
                  {isViewer ? 'View →' : action.buttonText}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── 6. FOOTER BANNER ───────────────────────────────────────────── */}
      <div className="si-footer-banner">
        <div className="si-fb-shield-box">R</div>
        <div className="si-fb-text">
          <strong>RizIntel turns vulnerability data into verified decisions.</strong> Less noise. More clarity. Stronger security.
        </div>
      </div>
    </div>
  );
}
