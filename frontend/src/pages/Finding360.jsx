import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import {
  getFindingById,
  getAssetDisplayName,
  submitAnalystFeedback,
  getFeedbackForFinding,
  fetchAuditTrail,
  verifyAuditTrail,
  getCurrentUser,
  ROLES
} from '../services/findingsService';
import {
  ArrowLeft, Shield, ShieldAlert, ShieldCheck, CheckCircle2, Clock,
  Flame, Globe, Target, AlertTriangle, TrendingUp, User, Copy, Check,
  Code, FileText, Lightbulb, ExternalLink, Activity, Zap, ArrowRight,
  HelpCircle, ArrowDown, EyeOff, Loader2, MessageSquare, Send, CheckSquare,
  Sparkles, Layers, ListChecks, Server, Database, ChevronRight, Lock,
  RefreshCw, CheckCheck, History, GitCommit, Key, ShieldX
} from 'lucide-react';
import RizTraceModal from '../components/finding360/RizTraceModal';
import { getMitreAttackContext } from '../utils/mitreAttack';

const TABS = [
  { id: 'overview', label: 'Overview', icon: Layers },
  { id: 'evidence', label: 'Evidence', icon: FileText },
  { id: 'journey', label: 'Journey', icon: Clock },
  { id: 'remediation', label: 'Remediation', icon: Code },
  { id: 'decision-activity', label: 'Decision & Activity', icon: User },
];

const DECISION_CONFIG = {
  ACCEPT_PRIORITY: { label: 'Accept Priority', color: 'green', desc: 'Confirm algorithmic risk score and SLA urgency.', roleMin: 'ANALYST' },
  ESCALATE:        { label: 'Escalate', color: 'orange', desc: 'Flag finding for immediate SOC lead escalation (Requires Security Lead / Admin).', roleMin: 'SECURITY_LEAD' },
  DOWNGRADE:       { label: 'Downgrade', color: 'amber', desc: 'Reduce urgency due to mitigating internal controls.', roleMin: 'ANALYST' },
  NEEDS_REVIEW:    { label: 'Needs Review', color: 'blue', desc: 'Request peer review and further payload testing.', roleMin: 'ANALYST' },
  FALSE_POSITIVE:  { label: 'False Positive', color: 'red', desc: 'Mark as non-exploitable scanner false alarm.', roleMin: 'ANALYST' },
};

export default function Finding360() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab');
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(initialTab || 'overview');
  const [showStickyBar, setShowStickyBar] = useState(false);

  // RBAC User Role state
  const [currentUser, setCurUser] = useState(() => getCurrentUser());
  const [rbacError, setRbacError] = useState(null);

  useEffect(() => {
    const handleAuthChange = () => {
      setCurUser(getCurrentUser());
      setRbacError(null);
    };
    window.addEventListener('rizintel-auth-change', handleAuthChange);
    return () => window.removeEventListener('rizintel-auth-change', handleAuthChange);
  }, []);

  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  const [copiedPoc, setCopiedPoc] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);

  // Decision State
  const [selectedDecision, setSelectedDecision] = useState('ACCEPT_PRIORITY');
  const [decisionRationale, setDecisionRationale] = useState('');
  const [submittingDecision, setSubmittingDecision] = useState(false);
  const [decisionSaved, setDecisionSaved] = useState(false);
  const [activeDecision, setActiveDecision] = useState(null);
  const [feedbackHistory, setFeedbackHistory] = useState([]);
  const [chainValid, setChainValid] = useState(true);

  // Activity Feed state
  const [activityList, setActivityList] = useState([
    {
      id: 1,
      type: 'red',
      icon: TrendingUp,
      headline: 'Risk score increased from 77 to 94',
      sub: 'KEV match detected and EPSS increased to 91%',
      time: '20 Aug, 01:30 PM'
    },
    {
      id: 2,
      type: 'green',
      icon: Flame,
      headline: 'CISA KEV match detected',
      sub: 'Vulnerability added to KEV catalog',
      time: '19 Aug, 08:30 PM'
    },
    {
      id: 3,
      type: 'teal',
      icon: Layers,
      headline: 'Finding correlated from 3 scanners',
      sub: 'Deduplicated into single risk',
      time: '18 Aug, 09:42 AM'
    },
    {
      id: 4,
      type: 'purple',
      icon: Zap,
      headline: 'First detected by ZAP scanner',
      sub: 'Initial finding created',
      time: '18 Aug, 09:10 AM'
    }
  ]);

  // Notes state
  const [notes, setNotes] = useState([
    {
      id: 1,
      author: 'SA Analyst',
      authorRole: 'Security Analyst',
      timestamp: '20 Aug 2026, 02:05 PM',
      text: 'Verified in staging. Issue is reproducible with single quote in id parameter. Impact: Can retrieve all payment records.'
    }
  ]);
  const [newNote, setNewNote] = useState('');

  // Remediation Plan Checklist state
  const [remediationSteps, setRemediationSteps] = useState([
    { id: 1, title: 'Identify all input parameters', desc: 'Map all user inputs in the payment API.', status: 'In Progress' },
    { id: 2, title: 'Implement parameterized queries', desc: 'Refactor queries to use prepared statements.', status: 'Not Started' },
    { id: 3, title: 'Input validation & sanitization', desc: 'Validate and sanitize all user inputs.', status: 'Not Started' },
    { id: 4, title: 'Deploy & verify', desc: 'Deploy changes to staging and verify.', status: 'Not Started' }
  ]);

  useEffect(() => {
    setLoading(true);
    getFindingById(id).then(async data => {
      setFinding(data);
      setLoading(false);
      if (data) {
        // Load persistent audit trail from SQLite backend
        const history = await fetchAuditTrail(data.finding_id);
        setFeedbackHistory(history || []);
        if (history && history.length > 0) {
          const latest = history[0];
          const action = latest.analyst_action || latest.analyst_decision || 'ACCEPT_PRIORITY';
          setSelectedDecision(action);
          setActiveDecision(latest);
        }
        const verifyRes = await verifyAuditTrail(data.finding_id);
        setChainValid(verifyRes?.valid !== false);
      }
    });
  }, [id]);

  // Track scroll for compact sticky finding bar
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 280) {
        setShowStickyBar(true);
      } else {
        setShowStickyBar(false);
      }
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleSaveDecision = async () => {
    if (!finding) return;
    setRbacError(null);

    // Frontend pre-check for clean UX before submitting
    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role is read-only. Decision overrides require Analyst, Security Lead, or Admin privileges.');
      return;
    }
    if (selectedDecision === 'ESCALATE' && !['SECURITY_LEAD', 'ADMIN'].includes(currentUser.role)) {
      setRbacError("Permission Denied (403): 'ESCALATE' action requires SOC Security Lead or Security Admin authority.");
      return;
    }

    setSubmittingDecision(true);
    try {
      const res = await submitAnalystFeedback(
        finding.finding_id,
        selectedDecision,
        decisionRationale,
        finding.risk_score
      );
      const updatedHistory = await fetchAuditTrail(finding.finding_id);
      setFeedbackHistory(updatedHistory || []);
      
      const newDecisionObj = res?.data || {
        finding_id: finding.finding_id,
        m5_risk_score: finding.risk_score,
        analyst_action: selectedDecision,
        analyst_decision: selectedDecision,
        rationale: decisionRationale,
        reason: decisionRationale,
        role: `${currentUser.name} [${currentUser.role}]`,
        timestamp: new Date().toISOString()
      };
      setActiveDecision(newDecisionObj);
      setDecisionSaved(true);

      const verifyRes = await verifyAuditTrail(finding.finding_id);
      setChainValid(verifyRes?.valid !== false);

      // Append real-time activity log
      const decisionConfig = DECISION_CONFIG[selectedDecision] || { label: selectedDecision, color: 'purple' };
      const newActivity = {
        id: Date.now(),
        type: decisionConfig.color,
        icon: User,
        headline: `Analyst Decision: ${decisionConfig.label}`,
        sub: decisionRationale ? `Rationale: "${decisionRationale}"` : `M5 Machine Score (${finding.risk_score}) preserved by ${currentUser.name} [${currentUser.role}]`,
        time: 'Just now'
      };
      setActivityList(prev => [newActivity, ...prev]);

      setTimeout(() => setDecisionSaved(false), 3500);
    } catch (err) {
      console.error(err);
      if (err.status === 403 || err.detail) {
        setRbacError(err.detail || err.message);
      } else {
        setRbacError(err.message || 'Failed to submit decision.');
      }
    } finally {
      setSubmittingDecision(false);
    }
  };

  const handleAddNote = () => {
    if (!newNote.trim()) return;
    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role cannot create investigation notes.');
      return;
    }
    const noteObj = {
      id: Date.now(),
      author: currentUser.name,
      authorRole: currentUser.config.label,
      timestamp: new Date().toLocaleString('en-US', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }),
      text: newNote.trim()
    };
    setNotes(prev => [noteObj, ...prev]);
    setNewNote('');
  };


  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    if (type === 'poc') {
      setCopiedPoc(true);
      setTimeout(() => setCopiedPoc(false), 2000);
    } else {
      setCopiedFix(true);
      setTimeout(() => setCopiedFix(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚡</div>
        <h3>Loading Investigation…</h3>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="empty-state">
        <AlertTriangle size={36} color="#EF4444" />
        <h3>Finding {id} not found</h3>
        <button className="btn btn-primary" onClick={() => navigate('/findings')} style={{ marginTop: 16 }}>
          Back to Findings Queue
        </button>
      </div>
    );
  }

  // Extract finding metadata
  const score = finding.risk_score ?? 94;
  const level = (finding.risk_level ?? 'CRITICAL').toUpperCase();
  const confidencePct = Math.round((finding.detail?.finding_confidence?.score ?? 0.96) * 100);
  const slaStatus = (finding.workflow?.sla_status ?? 'ON_TRACK').toUpperCase();
  const wfStatus = finding.workflow?.status ?? 'Open';
  const isKev = finding.detail?.threat_intelligence?.kev_listed ?? true;
  const epss = finding.detail?.threat_intelligence?.epss_score ?? 0.91;
  const isInternet = finding.internet_exposure !== false;
  const scannerCount = finding.detail?.scanner_consensus?.detected_by_count ?? 3;
  const totalScanners = finding.detail?.scanner_consensus?.total_scanners ?? 3;
  const assetName = getAssetDisplayName(finding.asset_id);
  const ac = finding.detail?.asset_context ?? {};

  // Custom Reasoning text
  const whyItMatters = finding.finding_id === 'DEDUP-0001'
    ? 'Known exploited vulnerability on a critical internet-facing payment API with high exploitation probability and confirmation from 3 scanners.'
    : finding.finding_id === 'DEDUP-0002'
    ? 'High impact unauthorized code execution on authentication service, potentially leading to full system compromise.'
    : finding.detail?.explanation?.technical || 'Identified threat vector on critical asset requiring prioritized remediation.';

  // Proof of Concept command / payload
  const pocPayload = finding.finding_id === 'DEDUP-0001'
    ? "GET /pay?id=1' OR '1'='1 HTTP/1.1"
    : finding.finding_id === 'DEDUP-0002'
    ? "POST /auth/api/v1/session HTTP/1.1\r\nPayload: eval(base64_decode('...'))"
    : `GET /api/v1/resource?target=${finding.asset_id} HTTP/1.1`;

  // Recommended Fix Code
  const fixCode = finding.finding_id === 'DEDUP-0001'
    ? `// Example: Using Prepared Statement\nString query = "SELECT * FROM payments WHERE id = ?";\nPreparedStatement stmt = conn.prepareStatement(query);\nstmt.setInt(1, id);\nResultSet rs = stmt.executeQuery();`
    : `// Example: Input Sanitization & Principle of Least Privilege\nif (!isValidInput(req.getParameter("input"))) {\n    throw new SecurityException("Invalid parameter detected");\n}\nauthService.validateSession(sessionToken);`;

  return (
    <div className="investigate-360-container">
      {/* ── Compact Sticky Finding Bar on Scroll ── */}
      <div className={`sticky-finding-compact-bar ${showStickyBar ? 'visible' : ''}`}>
        <div className="compact-bar-inner">
          <div className="compact-bar-left">
            <span className="compact-priority-badge">#01</span>
            <span className="compact-finding-title">{finding.vulnerability_name}</span>
            {finding.cve_id && <span className="compact-cve-tag">{finding.cve_id}</span>}
            <span className="compact-sep">•</span>
            <span className="compact-asset-name">{assetName}</span>
          </div>

          <div className="compact-bar-tabs">
            {TABS.map(({ id: tabId, label, icon: Icon }) => (
              <button
                key={tabId}
                className={`compact-tab-btn ${activeTab === tabId ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab(tabId);
                  window.scrollTo({ top: 220, behavior: 'smooth' });
                }}
              >
                <Icon size={13} />
                <span>{label}</span>
              </button>
            ))}
          </div>

          <div className="compact-bar-right">
            <div className="compact-score-pill">
              <span className="score-val">{score}</span>
              <span className="score-lbl">{level}</span>
            </div>
            <button
              className="compact-action-btn"
              onClick={() => setActiveTab('remediation')}
            >
              Remediate <ArrowRight size={13} />
            </button>
          </div>
        </div>
      </div>

      {/* ── 1. Top Navigation & Breadcrumb ── */}
      <div className="investigate-top-nav">
        <button className="investigate-back-btn" onClick={() => navigate('/findings')}>
          <ArrowLeft size={16} /> Back to Findings
        </button>
        <button
          className="top-nav-trace-btn"
          onClick={() => navigate(`/findings/${id}/riztrace`)}
          title="Open RizTrace Decision Provenance"
        >
          <GitCommit size={14} />
          <span>RizTrace Provenance</span>
        </button>
      </div>

      {/* ── 2. Top Finding Summary Hero Header ── */}
      <div className="investigate-hero-banner">
        <div className="investigate-hero-left">
          {/* Priority Pill */}
          <div className="investigate-priority-badge">
            #01 PRIORITY
          </div>

          {/* Title & CVE */}
          <div className="investigate-title-row">
            <h1 className="investigate-main-title">{finding.vulnerability_name}</h1>
            {finding.cve_id && (
              <span className="investigate-cve-pill">{finding.cve_id}</span>
            )}
          </div>

          {/* Asset Subtitle */}
          <div className="investigate-asset-subtext">
            <span className="asset-name-highlight">{assetName}</span>
            <span className="dot-sep">•</span>
            <span className="mono-code">{finding.asset_id}</span>
            <span className="dot-sep">•</span>
            <span className="mono-code">{finding.finding_id}</span>
          </div>

          {/* Telemetry Badges */}
          <div className="investigate-telemetry-row">
            {isKev && (
              <span className="inv-badge pink">
                <Flame size={13} /> CISA KEV
              </span>
            )}
            {epss != null && (
              <span className="inv-badge peach">
                <Target size={13} /> EPSS {(epss * 100).toFixed(0)}%
              </span>
            )}
            <span className="inv-badge blue">
              <Globe size={13} /> {isInternet ? 'Internet-Facing' : 'Internal Network'}
            </span>
            <span className="inv-badge green">
              <CheckCircle2 size={13} /> {scannerCount}/{totalScanners} Scanners
            </span>
          </div>
        </div>

        {/* Right KPI Metric Cards */}
        <div className="investigate-kpi-grid">
          {/* Card 1: Risk Score */}
          <div className="inv-kpi-card">
            <div className="inv-kpi-label">RISK SCORE</div>
            <div className="inv-kpi-number red">{score}</div>
            <div className="inv-kpi-pill red">{level}</div>
          </div>

          {/* Card 2: Confidence */}
          <div className="inv-kpi-card">
            <div className="inv-kpi-label">CONFIDENCE</div>
            <div className="inv-kpi-number dark">{confidencePct}%</div>
            <div className="inv-kpi-pill green">
              {finding.confidence_classification === 'CONFIRMED' ? 'Confirmed' : 'High Confidence'}
            </div>
          </div>

          {/* Card 3: SLA Status */}
          <div className="inv-kpi-card">
            <div className="inv-kpi-label">SLA STATUS</div>
            <div className="inv-kpi-status-text green">ON_TRACK</div>
            <div className="inv-kpi-subtext">On Track</div>
          </div>

          {/* Card 4: Workflow Status */}
          <div className="inv-kpi-card">
            <div className="inv-kpi-label">STATUS</div>
            <div className="inv-kpi-status-text blue">{wfStatus}</div>
            <div className="inv-kpi-subtext">{wfStatus}</div>
          </div>
        </div>
      </div>

      {/* ── 3. Action Bar / SLA Banner ── */}
      <div className="investigate-action-banner">
        <div className="action-banner-left">
          <div className="action-icon-circle purple">
            <Target size={20} />
          </div>
          <div className="action-text-group">
            <div className="action-mini-header">RECOMMENDED ACTION</div>
            <div className="action-description">
              {finding.recommended_action || 'Patch or mitigate immediately. Prioritize the internet-facing Fee Payment API before the SLA deadline.'}
            </div>
          </div>
        </div>

        <div className="action-banner-middle">
          <div className="action-icon-circle orange">
            <Clock size={20} />
          </div>
          <div className="action-text-group">
            <div className="action-mini-header">SLA REMAINING</div>
            <div className="action-sla-time">03h 42m</div>
          </div>
        </div>

        <div className="action-banner-right">
          <button
            className="action-btn-trace"
            id="btn-trace-decision"
            onClick={() => navigate(`/findings/${id}/riztrace`)}
          >
            <GitCommit size={15} />
            <span>Trace Decision</span>
          </button>
          <button
            className="action-btn-primary"
            onClick={() => setActiveTab('remediation')}
          >
            <span>Start Remediation</span>
            <ArrowRight size={15} />
          </button>
          <button
            className={`action-btn-secondary${currentUser.role === 'VIEWER' ? ' rbac-btn-disabled' : ''}`}
            onClick={() => {
              if (currentUser.role === 'VIEWER') {
                setRbacError('Permission Denied (403): VIEWER role cannot assign ticket owners.');
                setActiveTab('decision-activity');
                return;
              }
              alert(`Owner assigned for ticket ${finding.workflow?.ticket_id || 'VULN-0001'} by ${currentUser.name} [${currentUser.role}]`);
            }}
            disabled={currentUser.role === 'VIEWER'}
            title={currentUser.role === 'VIEWER' ? 'Viewer Role is Read-Only' : 'Assign Owner'}
          >
            <User size={15} />
            <span>Assign Owner</span>
          </button>
        </div>
      </div>

      {/* ── 4. 5 Interactive Navigation Tabs ── */}
      <div className="investigate-tabs-container">
        <div className="investigate-tabs-bar">
          {TABS.map(({ id: tabId, label, icon: Icon }) => (
            <button
              key={tabId}
              className={`inv-tab-btn ${activeTab === tabId ? 'active' : ''}`}
              onClick={() => setActiveTab(tabId)}
            >
              <Icon size={16} />
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ── 5. TAB 1: OVERVIEW (Minimal, High-Impact Summary) ── */}
      {activeTab === 'overview' && (
        <div className="investigate-tab-content fade-in">
          <div className="investigate-two-col-layout">
            {/* 1. Why This Is #1 (77 -> 94 Scoring & Risk Evolution) */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <TrendingUp size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Why This Is #1</h3>
                    <p className="inv-card-subtitle">Score escalation from 77 → 94 (+17 increase)</p>
                  </div>
                </div>
                <span className="risk-increased-badge">
                  <TrendingUp size={13} /> Score Escalated
                </span>
              </div>

              <div className="inv-card-body">
                {/* Visual Score Track */}
                <div className="evolution-track-container">
                  <div className="evolution-track-node">
                    <div className="ev-score-num muted">77</div>
                    <div className="ev-score-label">PREVIOUS<br />(3 days ago)</div>
                  </div>

                  <div className="evolution-line-wrapper">
                    <div className="ev-line-rail">
                      <div className="ev-dot-start" />
                      <div className="ev-line-gradient" />
                      <div className="ev-dot-end" />
                    </div>
                  </div>

                  <div className="evolution-track-node">
                    <div className="ev-score-num red">94</div>
                    <div className="ev-score-label">CURRENT</div>
                  </div>

                  <div className="evolution-delta-pill">
                    <div className="delta-number">+17</div>
                    <div className="delta-label">INCREASE</div>
                  </div>
                </div>

                {/* Plain-English Reasoning Box */}
                <div className="overview-why-matters-box">
                  <div className="why-matters-header">
                    <Lightbulb size={16} className="text-purple" />
                    <span className="why-matters-title">Executive Risk Justification</span>
                  </div>
                  <p className="why-matters-text">{whyItMatters}</p>
                </div>

                {/* 3 Contributing Factors */}
                <div className="evolution-factors-section">
                  <div className="factors-header-label">Key factors driving critical priority</div>
                  <div className="factors-cards-grid">
                    <div className="factor-mini-card red">
                      <div className="factor-delta-val">+8</div>
                      <div className="factor-info">
                        <div className="factor-title">CISA KEV Match</div>
                        <div className="factor-desc">Actively exploited in the wild</div>
                      </div>
                    </div>

                    <div className="factor-mini-card orange">
                      <div className="factor-delta-val">+5</div>
                      <div className="factor-info">
                        <div className="factor-title">Internet Exposure</div>
                        <div className="factor-desc">Direct public accessibility</div>
                      </div>
                    </div>

                    <div className="factor-mini-card peach">
                      <div className="factor-delta-val">+4</div>
                      <div className="factor-info">
                        <div className="factor-title">EPSS Increase</div>
                        <div className="factor-desc">Exploitability surged to 91%</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Risk DNA */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <Sparkles size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Risk DNA</h3>
                    <p className="inv-card-subtitle">5 fundamental pillars of this critical risk</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                <div className="risk-dna-items-list">
                  <div className="dna-item-row">
                    <div className="dna-icon-box purple">
                      <Target size={18} />
                    </div>
                    <div className="dna-content">
                      <div className="dna-title-row">
                        <span className="dna-title">Exploitability</span>
                        <span className="dna-badge red">High</span>
                      </div>
                      <p className="dna-desc">EPSS 91% and active weaponization in the wild.</p>
                    </div>
                  </div>

                  <div className="dna-item-row">
                    <div className="dna-icon-box purple">
                      <ShieldAlert size={18} />
                    </div>
                    <div className="dna-content">
                      <div className="dna-title-row">
                        <span className="dna-title">Asset Criticality</span>
                        <span className="dna-badge red">Critical</span>
                      </div>
                      <p className="dna-desc">Payment API is business tier-1 and high value.</p>
                    </div>
                  </div>

                  <div className="dna-item-row">
                    <div className="dna-icon-box purple">
                      <Globe size={18} />
                    </div>
                    <div className="dna-content">
                      <div className="dna-title-row">
                        <span className="dna-title">Exposure</span>
                        <span className="dna-badge orange">Internet-Facing</span>
                      </div>
                      <p className="dna-desc">Publicly accessible endpoint with no WAF protection.</p>
                    </div>
                  </div>

                  <div className="dna-item-row">
                    <div className="dna-icon-box purple">
                      <ShieldCheck size={18} />
                    </div>
                    <div className="dna-content">
                      <div className="dna-title-row">
                        <span className="dna-title">Data Sensitivity</span>
                        <span className="dna-badge blue">PCI</span>
                      </div>
                      <p className="dna-desc">Processes financial & cardholder transaction data.</p>
                    </div>
                  </div>

                  <div className="dna-item-row">
                    <div className="dna-icon-box purple">
                      <Flame size={18} />
                    </div>
                    <div className="dna-content">
                      <div className="dna-title-row">
                        <span className="dna-title">Threat Intel</span>
                        <span className="dna-badge red">CISA KEV</span>
                      </div>
                      <p className="dna-desc">Listed on CISA Known Exploited Vulnerabilities catalog.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* 3. Evidence Snapshot */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <FileText size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Evidence Snapshot</h3>
                    <p className="inv-card-subtitle">Verified by 3/3 scanner consensus</p>
                  </div>
                </div>
                <button
                  className="card-header-action-link"
                  onClick={() => setActiveTab('evidence')}
                >
                  Full Evidence <ArrowRight size={13} />
                </button>
              </div>

              <div className="inv-card-body">
                {/* PoC Preview */}
                <div className="poc-container">
                  <div className="poc-header">
                    <span className="poc-title">Proof of Concept Payload</span>
                    <span className="poc-subtitle">Tested & confirmed in staging environment</span>
                  </div>
                  <div className="poc-code-box">
                    <code>{pocPayload}</code>
                    <button
                      className="poc-copy-btn"
                      onClick={() => copyToClipboard(pocPayload, 'poc')}
                      title="Copy"
                    >
                      {copiedPoc ? <Check size={16} color="#10B981" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                {/* Consensus Summary Chips */}
                <div className="evidence-table" style={{ marginTop: 4 }}>
                  <div className="evidence-row">
                    <div className="evidence-scanner-name">
                      <Zap size={15} className="text-blue" />
                      <span>ZAP Scanner</span>
                    </div>
                    <span className="evidence-risk-tag red">High</span>
                    <span className="evidence-status-tag green">
                      <Check size={12} /> Confirmed
                    </span>
                  </div>

                  <div className="evidence-row">
                    <div className="evidence-scanner-name">
                      <Shield size={15} className="text-teal" />
                      <span>Nessus Professional</span>
                    </div>
                    <span className="evidence-risk-tag red">High</span>
                    <span className="evidence-status-tag green">
                      <Check size={12} /> Confirmed
                    </span>
                  </div>

                  <div className="evidence-row">
                    <div className="evidence-scanner-name">
                      <Globe size={15} className="text-green" />
                      <span>OpenVAS Network</span>
                    </div>
                    <span className="evidence-risk-tag orange">Medium</span>
                    <span className="evidence-status-tag green">
                      <Check size={12} /> Confirmed
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* 4. Asset & Exposure */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <Server size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Asset & Exposure</h3>
                    <p className="inv-card-subtitle">Target infrastructure and sensitivity profile</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                <div className="asset-context-grid">
                  <div className="asset-spec-item">
                    <span className="spec-label">Asset Name</span>
                    <span className="spec-value bold">{assetName}</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Asset ID</span>
                    <span className="spec-value mono">{finding.asset_id}</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Environment</span>
                    <span className="spec-badge blue">PRODUCTION</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Criticality</span>
                    <span className="spec-badge red">TIER-1 CRITICAL</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Network Exposure</span>
                    <span className="spec-badge orange">INTERNET-FACING</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Data Classification</span>
                    <span className="spec-badge purple">PCI-DSS COMPLIANT</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Asset Owner</span>
                    <span className="spec-value">Core Payments Team (ops@rizintel.io)</span>
                  </div>

                  <div className="asset-spec-item">
                    <span className="spec-label">Business Value</span>
                    <span className="spec-value bold">$1.2M Daily Processing Volume</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 6. TAB 2: EVIDENCE (Full Deep-Dive) ── */}
      {activeTab === 'evidence' && (
        <div className="investigate-tab-content fade-in">
          <div className="investigate-two-col-layout">
            {/* Full Technical Proof of Concept */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <Code size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Technical Proof of Concept</h3>
                    <p className="inv-card-subtitle">Verified exploit request with parameters</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                <div className="poc-container">
                  <div className="poc-header">
                    <span className="poc-title">HTTP Request Payload</span>
                    <span className="poc-subtitle">Simulated attack vector executing parameterized database query injection:</span>
                  </div>
                  <div className="poc-code-box">
                    <code>{pocPayload}</code>
                    <button
                      className="poc-copy-btn"
                      onClick={() => copyToClipboard(pocPayload, 'poc')}
                      title="Copy"
                    >
                      {copiedPoc ? <Check size={16} color="#10B981" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                <div className="raw-response-box">
                  <div className="raw-box-title">Scanner Verification Response</div>
                  <pre className="raw-pre">
{`HTTP/1.1 200 OK
Content-Type: application/json
Date: Thu, 20 Aug 2026 12:45:00 GMT

[
  { "id": 1, "card_holder": "John Doe", "card_token": "tok_991823a", "status": "APPROVED" },
  { "id": 2, "card_holder": "Alice Smith", "card_token": "tok_441299c", "status": "APPROVED" }
]`}
                  </pre>
                </div>
              </div>
            </div>

            {/* Aggregated Evidence Sources Table */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <FileText size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Evidence Sources & Consensus</h3>
                    <p className="inv-card-subtitle">Detailed scanner findings from 3 telemetry engines</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                <div className="evidence-table">
                  <div className="evidence-row">
                    <div className="evidence-scanner-name">
                      <Zap size={16} className="text-blue" />
                      <span>OWASP ZAP</span>
                    </div>
                    <span className="evidence-risk-tag red">High</span>
                    <span className="evidence-timestamp">Aug 20, 2026, 12:45 PM</span>
                    <span className="evidence-status-tag green">
                      <Check size={13} /> Confirmed
                    </span>
                  </div>

                  <div className="evidence-row">
                    <div className="evidence-scanner-name">
                      <Shield size={16} className="text-teal" />
                      <span>Nessus Pro</span>
                    </div>
                    <span className="evidence-risk-tag red">High</span>
                    <span className="evidence-timestamp">Aug 20, 2026, 12:32 PM</span>
                    <span className="evidence-status-tag green">
                      <Check size={13} /> Confirmed
                    </span>
                  </div>

                  <div className="evidence-row">
                    <div className="evidence-scanner-name">
                      <Globe size={16} className="text-green" />
                      <span>OpenVAS</span>
                    </div>
                    <span className="evidence-risk-tag orange">Medium</span>
                    <span className="evidence-timestamp">Aug 20, 2026, 11:58 AM</span>
                    <span className="evidence-status-tag green">
                      <Check size={13} /> Confirmed
                    </span>
                  </div>
                </div>

                <div className="consensus-summary-box">
                  <div className="cs-title">Consensus Analysis: 100% Agreement</div>
                  <p className="cs-desc">
                    All 3 autonomous engines independently discovered and flagged the unparameterized database query vulnerability at endpoint <code className="mono-code">/pay</code> on port 443.
                  </p>
                </div>
              </div>
            </div>

            {/* ── M8: MITRE ATT&CK Context Card (full-width below) ── */}
            {(() => {
              const mitre = getMitreAttackContext(finding);
              const confidenceColor = mitre.confidence === 'HIGH' ? 'red' : mitre.confidence === 'MEDIUM' ? 'amber' : 'blue';
              return (
                <div className="inv-card mitre-attack-card">
                  <div className="inv-card-header">
                    <div className="inv-card-title-group">
                      <div className="card-header-icon-box mitre-icon-box">
                        <Shield size={18} />
                      </div>
                      <div>
                        <h3 className="inv-card-title">MITRE ATT&amp;CK Context</h3>
                        <p className="inv-card-subtitle">M8 Enrichment · Contextual / Inferred — not a confirmed attack observation</p>
                      </div>
                    </div>
                    {mitre.isMapped && (
                      <span className="mitre-m8-badge">M8 Enrichment</span>
                    )}
                  </div>

                  <div className="inv-card-body">
                    {!mitre.isMapped ? (
                      <div className="mitre-not-mapped-state">
                        <ShieldCheck size={20} className="text-muted" />
                        <div>
                          <strong>Not Mapped</strong>
                          <p>{mitre.rationale}</p>
                        </div>
                      </div>
                    ) : (
                      <div className="mitre-mapped-content">
                        {/* Header row: Tactic → Technique */}
                        <div className="mitre-header-row">
                          <div className="mitre-tactic-block">
                            <span className="mitre-field-label">Tactic</span>
                            <div className="mitre-tactic-pill">
                              <span className="mitre-tactic-id">{mitre.tactic_id}</span>
                              <span className="mitre-tactic-name">{mitre.tactic}</span>
                            </div>
                          </div>
                          <span className="mitre-arrow">→</span>
                          <div className="mitre-technique-block">
                            <span className="mitre-field-label">Technique</span>
                            <div className="mitre-technique-pill">
                              <span className="mitre-tech-id">{mitre.technique_id}</span>
                              <span className="mitre-tech-name">{mitre.technique_name}</span>
                            </div>
                          </div>
                          {mitre.sub_technique && (
                            <>
                              <span className="mitre-arrow">→</span>
                              <div className="mitre-sub-block">
                                <span className="mitre-field-label">Sub-Technique</span>
                                <div className="mitre-sub-pill">
                                  {mitre.sub_technique_id && <span className="mitre-tech-id">{mitre.sub_technique_id}</span>}
                                  <span className="mitre-tech-name">{mitre.sub_technique}</span>
                                </div>
                              </div>
                            </>
                          )}
                          <div className="mitre-confidence-block">
                            <span className="mitre-field-label">Confidence</span>
                            <span className={`mitre-confidence-badge ${confidenceColor}`}>{mitre.confidence}</span>
                          </div>
                        </div>

                        {/* Rationale */}
                        <div className="mitre-rationale-box">
                          <span className="mitre-rationale-icon"><Lightbulb size={13} /></span>
                          <p className="mitre-rationale-text">{mitre.rationale}</p>
                        </div>

                        {/* Footer: Source + Link */}
                        <div className="mitre-footer-row">
                          <span className="mitre-source-chip">
                            <Database size={11} /> {mitre.source}
                          </span>
                          <a
                            href={mitre.mitre_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="mitre-link-btn"
                          >
                            <ExternalLink size={11} />
                            View on MITRE ATT&CK
                          </a>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* ── 7. TAB 3: JOURNEY (Timeline & Milestones) ── */}
      {activeTab === 'journey' && (
        <div className="investigate-tab-content fade-in">
          <div className="inv-card">
            <div className="inv-card-header">
              <div className="inv-card-title-group">
                <div className="card-header-icon-box purple">
                  <Clock size={18} />
                </div>
                <div>
                  <h3 className="inv-card-title">Finding Lifecycle Journey</h3>
                  <p className="inv-card-subtitle">Complete chronological milestone history</p>
                </div>
              </div>
              <span className="journey-summary-chip">
                5 Milestones Recorded
              </span>
            </div>

            <div className="inv-card-body">
              <div className="journey-timeline-horizontal">
                {/* Step 1 */}
                <div className="journey-node-item">
                  <div className="journey-node-icon-box">
                    <Zap size={16} />
                  </div>
                  <div className="journey-node-title">First Detected</div>
                  <div className="journey-node-time">Aug 18, 2026, 09:10 AM</div>
                  <div className="journey-node-desc">By ZAP Scanner</div>
                </div>

                <div className="journey-line-segment done" />

                {/* Step 2 */}
                <div className="journey-node-item">
                  <div className="journey-node-icon-box">
                    <Layers size={16} />
                  </div>
                  <div className="journey-node-title">Correlated & Deduped</div>
                  <div className="journey-node-time">Aug 18, 2026, 09:42 AM</div>
                  <div className="journey-node-desc">3 signals correlated</div>
                </div>

                <div className="journey-line-segment done" />

                {/* Step 3 */}
                <div className="journey-node-item">
                  <div className="journey-node-icon-box">
                    <Shield size={16} />
                  </div>
                  <div className="journey-node-title">Risk Assessed</div>
                  <div className="journey-node-time">Aug 18, 2026, 10:15 AM</div>
                  <div className="journey-node-desc">Initial score: 77</div>
                </div>

                <div className="journey-line-segment done" />

                {/* Step 4 */}
                <div className="journey-node-item">
                  <div className="journey-node-icon-box">
                    <Sparkles size={16} />
                  </div>
                  <div className="journey-node-title">Intelligence Update</div>
                  <div className="journey-node-time">Aug 19, 2026, 08:30 PM</div>
                  <div className="journey-node-desc">KEV match + EPSS update</div>
                </div>

                <div className="journey-line-segment active" />

                {/* Step 5 */}
                <div className="journey-node-item highlight">
                  <div className="journey-node-icon-box red">
                    <TrendingUp size={16} />
                  </div>
                  <div className="journey-node-title red">Score Increased</div>
                  <div className="journey-node-time">Aug 20, 2026, 01:30 PM</div>
                  <div className="journey-node-desc bold">Current score: 94 (+17)</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 8. TAB 4: REMEDIATION (Fix, Checklist & Tasks) ── */}
      {activeTab === 'remediation' && (
        <div className="investigate-tab-content fade-in">
          <div className="investigate-two-col-layout">
            {/* Left: Recommended Fix & Code */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <Code size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Remediation Guidance</h3>
                    <p className="inv-card-subtitle">Recommended secure coding fix and references</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                <div className="remediation-fix-block">
                  <div className="fix-header-label">Recommended Fix</div>
                  <p className="fix-desc">
                    Use parameterized queries or prepared statements to prevent SQL Injection.
                  </p>

                  <div className="fix-code-container">
                    <pre className="fix-code-pre">
                      <code>{fixCode}</code>
                    </pre>
                    <button
                      className="fix-copy-btn"
                      onClick={() => copyToClipboard(fixCode, 'fix')}
                      title="Copy code"
                    >
                      {copiedFix ? <Check size={16} color="#10B981" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                <div className="remediation-references-block">
                  <div className="ref-header-label">External References</div>
                  <div className="ref-links-list">
                    <a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noreferrer" className="ref-link-item">
                      OWASP SQL Injection Prevention Cheat Sheet <ArrowRight size={14} />
                    </a>
                    <a href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id || 'CVE-2026-1234'}`} target="_blank" rel="noreferrer" className="ref-link-item">
                      {finding.cve_id || 'CVE-2026-1234'} NIST NVD Details <ArrowRight size={14} />
                    </a>
                    <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer" className="ref-link-item">
                      CISA Known Exploited Vulnerabilities Catalog <ArrowRight size={14} />
                    </a>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Remediation Plan Checklist */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <CheckSquare size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Remediation Plan</h3>
                    <p className="inv-card-subtitle">4-step implementation checklist</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                <div className="remediation-steps-list">
                  {remediationSteps.map(step => (
                    <div key={step.id} className="rem-step-row">
                      <div className="rem-step-num">{step.id}</div>
                      <div className="rem-step-content">
                        <div className="rem-step-title">{step.title}</div>
                        <div className="rem-step-desc">{step.desc}</div>
                      </div>
                      <span className={`rem-step-status-tag${step.status === 'In Progress' ? ' in-progress' : ''}`}>
                        {step.status}
                      </span>
                    </div>
                  ))}
                </div>

                <button
                  className="create-remediation-task-btn"
                  onClick={() => alert(`Task created in Jira/ServiceNow for ${finding.workflow?.ticket_id || 'VULN-0001'}`)}
                >
                  <span>Create Remediation Task</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 9. TAB 5: DECISION & ACTIVITY (Fully Functional) ── */}
      {activeTab === 'decision-activity' && (
        <div className="investigate-tab-content fade-in">
          <div className="investigate-two-col-layout">
            {/* Analyst Decision Panel */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <User size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Analyst Decision</h3>
                    <p className="inv-card-subtitle">Validate or override RizIntel's recommendation</p>
                  </div>
                </div>
                {activeDecision && (
                  <span className={`active-decision-chip ${DECISION_CONFIG[activeDecision.analyst_decision]?.color || 'green'}`}>
                    <CheckCircle2 size={13} /> Active: {DECISION_CONFIG[activeDecision.analyst_decision]?.label || activeDecision.analyst_decision}
                  </span>
                )}
              </div>

              <div className="inv-card-body">
                {/* RBAC Viewer / Permission Alert */}
                {currentUser.role === 'VIEWER' && (
                  <div className="rbac-permission-notice viewer fade-in">
                    <Lock size={15} className="text-muted" />
                    <div>
                      <strong>Viewer Role (Read-Only)</strong>
                      <p>You have read-only inspection access. Decision recording and priority overrides require Analyst, Security Lead, or Admin privileges.</p>
                    </div>
                  </div>
                )}

                {/* 403 Forbidden Error Alert */}
                {rbacError && (
                  <div className="rbac-error-banner fade-in">
                    <ShieldAlert size={16} color="#EF4444" />
                    <div>
                      <strong>Access Denied (HTTP 403)</strong>
                      <p>{rbacError}</p>
                    </div>
                    <button className="rbac-dismiss-btn" onClick={() => setRbacError(null)} title="Dismiss">
                      <X size={13} />
                    </button>
                  </div>
                )}

                {/* Decision Alert Banner if decision is saved */}
                {decisionSaved && (
                  <div className="decision-success-banner fade-in">
                    <CheckCircle2 size={18} color="#16A34A" />
                    <div>
                      <strong>Decision Successfully Recorded in Audit Trail!</strong>
                      <p>
                        Selected "{DECISION_CONFIG[selectedDecision]?.label}" by {currentUser.name} [{currentUser.role}]. Cryptographic SHA-256 chain updated.
                      </p>
                    </div>
                  </div>
                )}

                {/* 5 Decision Pills with RBAC permissions & tooltips */}
                <div className="decision-actions-row">
                  {Object.entries(DECISION_CONFIG).map(([key, config]) => {
                    const isSelected = selectedDecision === key;
                    const isViewer = currentUser.role === 'VIEWER';
                    const isEscalateRestricted = key === 'ESCALATE' && !['SECURITY_LEAD', 'ADMIN'].includes(currentUser.role);
                    const isDisabled = isViewer || isEscalateRestricted;

                    return (
                      <button
                        key={key}
                        className={`decision-pill-btn ${config.color}${isSelected ? ' active' : ''}${isDisabled ? ' rbac-disabled' : ''}`}
                        onClick={() => {
                          if (isViewer) {
                            setRbacError('Permission Denied (403): VIEWER role cannot select or record decisions.');
                            return;
                          }
                          if (isEscalateRestricted) {
                            setRbacError("Permission Denied (403): 'ESCALATE' action requires SOC Security Lead or Security Admin authority.");
                            return;
                          }
                          setSelectedDecision(key);
                        }}
                        disabled={isDisabled}
                        title={
                          isViewer ? 'Read-Only (Viewer Role)' :
                          isEscalateRestricted ? 'Requires Security Lead or Admin' :
                          config.desc
                        }
                      >
                        {key === 'ACCEPT_PRIORITY' && <Check size={14} />}
                        {key === 'ESCALATE' && <ShieldAlert size={14} />}
                        {key === 'DOWNGRADE' && <ArrowDown size={14} />}
                        {key === 'NEEDS_REVIEW' && <HelpCircle size={14} />}
                        {key === 'FALSE_POSITIVE' && <EyeOff size={14} />}
                        <span>{config.label}</span>
                        {isEscalateRestricted && (
                          <span className="rbac-lock-tag" title="Restricted to Lead/Admin">
                            <Lock size={10} /> Lead Only
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* Selected Option Description */}
                <div className="decision-selected-desc-box">
                  <span className="desc-box-label">Action Description:</span>
                  <span className="desc-box-text">
                    {DECISION_CONFIG[selectedDecision]?.desc || ''}
                  </span>
                </div>

                {/* Decision Rationale Input */}
                <div className="decision-input-section">
                  <label className="decision-input-label">Decision Rationale & Auditor Notes (optional)</label>
                  <div className="decision-input-group">
                    <input
                      type="text"
                      placeholder={currentUser.role === 'VIEWER' ? 'Read-only mode (switch role to edit)...' : 'e.g., Staging verified, active exploitation confirmed...'}
                      value={decisionRationale}
                      onChange={e => setDecisionRationale(e.target.value)}
                      className="decision-text-field"
                      disabled={currentUser.role === 'VIEWER'}
                      onKeyDown={e => e.key === 'Enter' && handleSaveDecision()}
                    />
                    <button
                      className={`save-decision-btn${currentUser.role === 'VIEWER' ? ' rbac-btn-disabled' : ''}`}
                      onClick={handleSaveDecision}
                      disabled={submittingDecision || currentUser.role === 'VIEWER'}
                      title={currentUser.role === 'VIEWER' ? 'Viewer Role is Read-Only' : 'Save Analyst Decision'}
                    >
                      {submittingDecision ? (
                        <><Loader2 size={14} className="spin" /> Saving…</>
                      ) : decisionSaved ? (
                        <><CheckCheck size={15} /> Saved!</>
                      ) : currentUser.role === 'VIEWER' ? (
                        <><Lock size={14} /> Read-Only</>
                      ) : (
                        <><Check size={15} /> Save Decision</>
                      )}
                    </button>
                  </div>
                </div>

                {/* Persistent Tamper-Evident Audit History */}
                {feedbackHistory.length > 0 && (
                  <div className="decision-history-section">
                    <div className="history-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <History size={14} className="text-purple" />
                        <span>Cryptographic Decision Audit Trail ({feedbackHistory.length} Event{feedbackHistory.length > 1 ? 's' : ''})</span>
                      </div>
                      <span className={`audit-chain-badge ${chainValid ? 'valid' : 'invalid'}`}>
                        <ShieldCheck size={12} />
                        <span>{chainValid ? 'SHA-256 Chain Intact' : 'Chain Warning'}</span>
                      </span>
                    </div>
                    <div className="history-items-list">
                      {feedbackHistory.map((item, idx) => {
                        const actionKey = item.analyst_action || item.analyst_decision || 'ACCEPT_PRIORITY';
                        const cfg = DECISION_CONFIG[actionKey] || { label: actionKey.replace(/_/g, ' '), color: 'purple' };
                        const scoreVal = item.m5_risk_score != null ? item.m5_risk_score : finding.risk_score;
                        const rationaleText = item.rationale || item.reason;
                        const roleName = item.role ? item.role.replace(/_/g, ' ') : 'Security Analyst';

                        return (
                          <div key={item.event_hash || item.id || idx} className="history-item-row audit-event-card">
                            <div className="history-item-top">
                              <div className="history-item-left">
                                <span className={`history-badge ${cfg.color}`}>{cfg.label}</span>
                                <span className="history-score-tag" title="Original M5 Risk Score (Preserved Separately)">
                                  M5 Score: <strong>{scoreVal}</strong>
                                </span>
                                <span className="history-author">by {roleName}</span>
                              </div>
                              <span className="history-time" title={item.timestamp}>
                                {item.timestamp ? new Date(item.timestamp).toLocaleString([], {
                                  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                                }) : 'Recorded'}
                              </span>
                            </div>

                            {rationaleText && (
                              <div className="history-reason-box">
                                <span className="history-reason">"{rationaleText}"</span>
                              </div>
                            )}

                            {item.event_hash && (
                              <div className="history-hash-row">
                                <div className="history-hash-item" title={`SHA-256 Event Hash: ${item.event_hash}`}>
                                  <Key size={11} className="text-purple" />
                                  <span className="hash-label">Hash:</span>
                                  <code className="hash-code">{item.event_hash.slice(0, 16)}…</code>
                                </div>
                                <div className="history-hash-item" title={`Previous Event Hash: ${item.previous_hash || 'GENESIS'}`}>
                                  <span className="hash-label">Prev:</span>
                                  <code className="hash-code">{(item.previous_hash || 'GENESIS').slice(0, 12)}…</code>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="decision-audit-note">
                  <HelpCircle size={15} className="note-icon" />
                  <span>Tamper-evident audit trail backed by SQLite. Each analyst decision is chained with SHA-256 hashes while preserving original M5 machine assessments intact.</span>
                </div>
              </div>
            </div>

            {/* Recent Activity & Notes */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple">
                    <Activity size={18} />
                  </div>
                  <div>
                    <h3 className="inv-card-title">Activity Feed & Notes</h3>
                    <p className="inv-card-subtitle">Real-time audit log and team collaboration</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body">
                {/* Note Input */}
                <div className="note-input-container">
                  <textarea
                    placeholder="Write investigation notes..."
                    value={newNote}
                    onChange={e => setNewNote(e.target.value)}
                    className="note-textarea"
                    rows={2}
                  />
                  <div className="note-submit-row">
                    <button
                      className="add-note-btn"
                      onClick={handleAddNote}
                      disabled={!newNote.trim()}
                    >
                      <Send size={13} /> Add Note
                    </button>
                  </div>
                </div>

                {/* Note History */}
                <div className="notes-history-list">
                  {notes.map(n => (
                    <div key={n.id} className="note-item-box">
                      <div className="note-header">
                        <div className="note-author-group">
                          <div className="note-avatar">SA</div>
                          <div>
                            <span className="note-author-name">{n.author}</span>
                            <span className="note-time">{n.timestamp}</span>
                          </div>
                        </div>
                      </div>
                      <p className="note-text-body">{n.text}</p>
                    </div>
                  ))}
                </div>

                {/* Real-time Activity Feed */}
                <div className="activity-timeline-list" style={{ marginTop: 14 }}>
                  {activityList.map(item => {
                    const ItemIcon = item.icon;
                    return (
                      <div key={item.id} className="activity-item-row fade-in">
                        <div className={`activity-icon-dot ${item.type}`}>
                          <ItemIcon size={14} />
                        </div>
                        <div className="activity-details">
                          <div className="activity-headline">{item.headline}</div>
                          <div className="activity-sub">{item.sub}</div>
                        </div>
                        <div className="activity-time">{item.time}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
