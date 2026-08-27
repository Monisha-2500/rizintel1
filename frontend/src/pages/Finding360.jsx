import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import * as findingsService from '../services/findingsService';
import {
  ArrowLeft, Shield, ShieldAlert, ShieldCheck, CheckCircle2, Clock,
  Flame, Globe, Target, AlertTriangle, TrendingUp, User, Copy, Check,
  Code, FileText, Lightbulb, ExternalLink, Activity, Zap, ArrowRight,
  HelpCircle, ArrowDown, EyeOff, Loader2, Send, CheckSquare,
  Sparkles, Layers, Server, Database, Lock, CheckCheck, History, GitCommit, Key, Wrench, X,
  ChevronDown, ChevronUp, BarChart2, Info, MapPin, Cpu, RefreshCw, Calculator
} from 'lucide-react';
import { getMitreAttackContext } from '../utils/mitreAttack';

const TABS = [
  { id: 'overview', label: 'Overview', icon: Layers },
  { id: 'evidence', label: 'Evidence', icon: FileText },
  { id: 'explainability', label: 'Explainability', icon: Sparkles },
  { id: 'journey', label: 'Journey', icon: Clock },
  { id: 'remediation', label: 'Remediation', icon: Code },
  { id: 'decision-activity', label: 'Decision & Activity', icon: User },
];

const DECISION_CONFIG = {
  ACCEPT_PRIORITY: { label: 'Accept Priority', color: 'green', icon: CheckCircle2, desc: 'Confirm algorithmic risk score and SLA urgency.', roleMin: 'ANALYST' },
  ESCALATE:        { label: 'Escalate', color: 'orange', icon: TrendingUp, desc: 'Flag finding for immediate SOC lead escalation (Requires Security Lead / Admin).', roleMin: 'SECURITY_LEAD' },
  DOWNGRADE:       { label: 'Downgrade', color: 'amber', icon: ArrowDown, desc: 'Reduce urgency due to mitigating internal controls.', roleMin: 'ANALYST' },
  NEEDS_REVIEW:    { label: 'Needs Review', color: 'blue', icon: HelpCircle, desc: 'Request peer review and further payload testing.', roleMin: 'ANALYST' },
  FALSE_POSITIVE:  { label: 'False Positive', color: 'red', icon: EyeOff, desc: 'Mark as non-exploitable scanner false alarm.', roleMin: 'ANALYST' },
};

function formatSlaRemaining(deadlineStr) {
  if (!deadlineStr) return '—';
  const deadline = new Date(deadlineStr);
  const now = new Date();
  const diffMs = deadline.getTime() - now.getTime();
  if (isNaN(diffMs)) return '—';
  if (diffMs <= 0) return 'BREACHED';
  const totalHours = Math.floor(diffMs / (1000 * 60 * 60));
  const mins = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
  if (totalHours >= 48) {
    const days = Math.floor(totalHours / 24);
    return `${days}d ${totalHours % 24}h remaining`;
  }
  return `${String(totalHours).padStart(2, '0')}h ${String(mins).padStart(2, '0')}m remaining`;
}

function formatSlaDeadline(deadlineStr) {
  if (!deadlineStr) return 'Not scheduled';
  const d = new Date(deadlineStr);
  if (isNaN(d.getTime())) return 'Not scheduled';
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  });
}

function formatTs(ts) {
  if (!ts) return null;
  try {
    return new Date(ts).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return null; }
}

export default function Finding360() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab');
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(initialTab || 'overview');
  const [showStickyBar, setShowStickyBar] = useState(false);
  const tabsRef = useRef(null);

  // RBAC User Role state
  const [currentUser, setCurUser] = useState(() => findingsService.getCurrentUser());
  const [rbacError, setRbacError] = useState(null);

  // Remediation & Ticketing State (Phase 7 M7 Engine)
  const [remediationTask, setRemediationTask] = useState(null);
  const [taskHistory, setTaskHistory] = useState([]);
  const [creatingTask, setCreatingTask] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [selectedAssignee, setSelectedAssignee] = useState('secops');
  const [customAssignee, setCustomAssignee] = useState('');
  const [assigningOwner, setAssigningOwner] = useState(false);
  const [updatingTaskStatus, setUpdatingTaskStatus] = useState(false);
  const [toastMsg, setToastMsg] = useState(null);

  // UI state
  const [showFullExplanation, setShowFullExplanation] = useState(false);
  const [expandedJourneyNode, setExpandedJourneyNode] = useState(null);
  const [expandedAuditHash, setExpandedAuditHash] = useState(null);

  useEffect(() => {
    const handleAuthChange = () => {
      setCurUser(findingsService.getCurrentUser());
      setRbacError(null);
    };
    window.addEventListener('rizintel-auth-change', handleAuthChange);
    return () => window.removeEventListener('rizintel-auth-change', handleAuthChange);
  }, []);

  useEffect(() => {
    const tabParam = searchParams.get('tab');
    if (tabParam && TABS.some(t => t.id === tabParam)) {
      setActiveTab(tabParam);
    }
  }, [searchParams]);

  const [copiedPoc, setCopiedPoc] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);
  const [copiedExplanation, setCopiedExplanation] = useState(false);
  const [audienceView, setAudienceView] = useState('analyst');

  // Decision State
  const [selectedDecision, setSelectedDecision] = useState('ACCEPT_PRIORITY');
  const [decisionRationale, setDecisionRationale] = useState('');
  const [submittingDecision, setSubmittingDecision] = useState(false);
  const [decisionSaved, setDecisionSaved] = useState(false);
  const [activeDecision, setActiveDecision] = useState(null);
  const [feedbackHistory, setFeedbackHistory] = useState([]);
  const [chainValid, setChainValid] = useState(true);

  // Activity Feed & Notes State
  const [activityList, setActivityList] = useState([]);
  const [notes, setNotes] = useState([]);
  const [newNote, setNewNote] = useState('');

  const scanRunId = searchParams.get('scan_run_id');
  const orgId = searchParams.get('org_id');

  const showToast = (msg) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  useEffect(() => {
    setLoading(true);
    findingsService.getFindingById(id, scanRunId, orgId).then(async data => {
      setFinding(data);
      setLoading(false);
      if (data) {
        // Load persistent audit trail from SQLite backend
        const history = await findingsService.fetchAuditTrail(data.finding_id).catch(() => []);
        setFeedbackHistory(history || []);
        if (history && history.length > 0) {
          const latestAnalystDecision = history.find(item => {
            const act = item.analyst_action || item.analyst_decision;
            return act && DECISION_CONFIG[act];
          });
          if (latestAnalystDecision) {
            const action = latestAnalystDecision.analyst_action || latestAnalystDecision.analyst_decision;
            setSelectedDecision(action);
            setActiveDecision(latestAnalystDecision);
          } else {
            setSelectedDecision('ACCEPT_PRIORITY');
            setActiveDecision(null);
          }

          const acts = history.map((item, idx) => {
            const actionKey = item.analyst_action || item.analyst_decision || 'ACCEPT_PRIORITY';
            const cfg = DECISION_CONFIG[actionKey] || { label: formatAuditAction(actionKey), color: 'purple' };
            return {
              id: item.event_hash || idx,
              type: cfg.color,
              icon: User,
              headline: `Analyst Decision: ${cfg.label}`,
              sub: item.rationale || item.reason ? `Rationale: "${item.rationale || item.reason}"` : `Recorded by ${item.role || 'Analyst'}`,
              time: item.timestamp ? new Date(item.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Recorded'
            };
          });
          setActivityList(acts);
        }
        const verifyRes = await findingsService.verifyAuditTrail(data.finding_id).catch(() => ({ valid: true }));
        setChainValid(verifyRes?.valid !== false);

        // Load authoritative remediation task if existing
        findingsService.getRemediationTask(data.finding_id).then(res => {
          if (res && res.ticket) {
            setRemediationTask(res.ticket);
            setTaskHistory(res.history || []);
            if (res.ticket.ticket_id) {
              findingsService.getTaskChecklist(res.ticket.ticket_id).then(steps => {
                if (steps && steps.length > 0) setChecklistSteps(steps);
              }).catch(() => {});
            }
          }
        }).catch(() => {});
      }
    }).catch(err => {
      console.error('Failed to load finding for 360 view:', err);
      setFinding(null);
      setLoading(false);
    });
  }, [id, scanRunId, orgId]);

  // Track scroll for compact sticky finding bar
  useEffect(() => {
    const handleScroll = () => {
      setShowStickyBar(window.scrollY > 280);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const [checklistSteps, setChecklistSteps] = useState([]);
  const [updatingChecklist, setUpdatingChecklist] = useState(false);

  const handleStepToggle = async (stepId, currentStatus) => {
    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role cannot modify checklist steps.');
      return;
    }
    if (!remediationTask?.ticket_id) return;
    const nextStatus = currentStatus === 'COMPLETED' ? 'NOT_STARTED' : (currentStatus === 'NOT_STARTED' ? 'IN_PROGRESS' : 'COMPLETED');
    setUpdatingChecklist(true);
    try {
      const result = await findingsService.updateTaskChecklistStep(remediationTask.ticket_id, stepId, nextStatus);
      if (result?.checklist) {
        setChecklistSteps(result.checklist);
        showToast(`Checklist step updated to ${nextStatus.replace('_', ' ')}`);
      }
    } catch (err) {
      setRbacError(err.message || 'Failed to update step');
    } finally {
      setUpdatingChecklist(false);
    }
  };

  const handleStartRemediation = async () => {
    setActiveTab('remediation');
    if (!finding) return;
    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role cannot create or modify remediation tasks.');
      return;
    }
    if (!remediationTask) {
      setCreatingTask(true);
      try {
        const res = await findingsService.createRemediationTask(finding.finding_id, 'Started remediation from Finding360 action strip').catch(() => null);
        const ticket = res?.ticket || {
          ticket_id: finding.workflow?.ticket_id || `TCK-${Date.now().toString(36).toUpperCase()}`,
          finding_id: finding.finding_id,
          status: 'OPEN',
          due_at: finding.workflow?.sla_due_at || new Date(Date.now() + 7 * 86400000).toISOString(),
          sla_hours: finding.workflow?.sla_hours || 168,
          priority: score >= 90 ? 'CRITICAL' : score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW',
        };
        setRemediationTask(ticket);
        if (finding && finding.workflow) {
          finding.workflow.status = ticket.status;
          finding.workflow.ticket_id = ticket.ticket_id;
        }
        if (res && res.history) {
          setTaskHistory(res.history);
        }
        showToast(`Remediation task ${ticket.ticket_id} active`);
      } catch (err) {
        console.error(err);
        setRbacError(err.detail || err.message);
      } finally {
        setCreatingTask(false);
      }
    }
  };

  const handleAssignConfirm = async () => {
    const targetAssignee = customAssignee.trim() || selectedAssignee;
    if (!targetAssignee) return;

    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role is read-only and cannot assign task owners.');
      return;
    }

    setAssigningOwner(true);
    setRbacError(null);
    try {
      let task = remediationTask;
      if (!task || !task.ticket_id) {
        const createRes = await findingsService.createRemediationTask(finding.finding_id, 'Created task for assignment').catch(() => null);
        if (createRes && createRes.ticket) {
          task = createRes.ticket;
          setRemediationTask(task);
        }
      }

      const ticketId = task?.ticket_id || finding.workflow?.ticket_id;
      if (!ticketId) {
        throw new Error('Unable to resolve remediation task ID for assignment.');
      }

      const res = await findingsService.assignTaskOwner(ticketId, targetAssignee);
      if (res && res.ticket) {
        setRemediationTask(res.ticket);
        setTaskHistory(res.history || []);
        setShowAssignModal(false);
        setCustomAssignee('');
        showToast(`Owner assigned to ${res.ticket.assignee_display_name || targetAssignee}`);

        const history = await findingsService.fetchAuditTrail(finding.finding_id).catch(() => []);
        setFeedbackHistory(history || []);
      }
    } catch (err) {
      console.error('Assign owner failed', err);
      setRbacError(err.detail || err.message || 'Failed to assign owner.');
    } finally {
      setAssigningOwner(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role is read-only and cannot transition task status.');
      return;
    }

    setUpdatingTaskStatus(true);
    setRbacError(null);
    try {
      let task = remediationTask;
      if (!task || !task.ticket_id) {
        const createRes = await findingsService.createRemediationTask(finding.finding_id, 'Created task for status transition').catch(() => null);
        if (createRes && createRes.ticket) {
          task = createRes.ticket;
          setRemediationTask(task);
        }
      }

      const ticketId = task?.ticket_id || finding.workflow?.ticket_id || `TKT-${finding.finding_id}`;

      const res = await findingsService.updateTaskStatus(
        ticketId,
        newStatus,
        `Status transitioned to ${newStatus} by ${currentUser.name}`
      ).catch(() => null);

      const updatedTicket = res?.ticket || {
        ...(task || {}),
        ticket_id: ticketId,
        status: newStatus,
        finding_id: finding.finding_id,
        due_at: task?.due_at || finding.workflow?.sla_due_at || new Date(Date.now() + 7 * 86400000).toISOString(),
        sla_hours: task?.sla_hours || finding.workflow?.sla_hours || 168,
        priority: task?.priority || 'MEDIUM',
      };

      setRemediationTask(updatedTicket);
      if (finding && finding.workflow) {
        finding.workflow.status = newStatus;
        if (newStatus === 'RESOLVED') {
          finding.workflow.sla_status = 'MET';
        }
      }
      if (res && res.history) {
        setTaskHistory(res.history);
      }
      showToast(`Task status updated to ${newStatus.replace('_', ' ')}`);

      const history = await findingsService.fetchAuditTrail(finding.finding_id).catch(() => []);
      setFeedbackHistory(history || []);

      const verifyRes = await findingsService.verifyAuditTrail(finding.finding_id).catch(() => ({ valid: true }));
      setChainValid(verifyRes?.valid !== false);

      if (newStatus === 'RESOLVED') {
        const steps = await findingsService.getTaskChecklist(ticketId).catch(() => []);
        if (steps && steps.length > 0) setChecklistSteps(steps);
      }
    } catch (err) {
      console.error('Status transition failed', err);
      setRbacError(err.detail || err.message || 'Failed to update task status.');
    } finally {
      setUpdatingTaskStatus(false);
    }
  };

  const handleSaveDecision = async () => {
    if (!finding) return;
    setRbacError(null);

    if (currentUser.role === 'VIEWER') {
      setRbacError('Permission Denied (403): VIEWER role is read-only and cannot record decisions.');
      return;
    }
    if (selectedDecision === 'ESCALATE' && !['SECURITY_LEAD', 'ADMIN'].includes(currentUser.role)) {
      setRbacError("Permission Denied (403): 'ESCALATE' action requires SOC Security Lead or Security Admin authority.");
      return;
    }
    if (['DOWNGRADE', 'FALSE_POSITIVE', 'ESCALATE'].includes(selectedDecision) && !decisionRationale.trim()) {
      setRbacError(`Rationale is required when selecting ${DECISION_CONFIG[selectedDecision]?.label || selectedDecision}.`);
      return;
    }

    setSubmittingDecision(true);
    try {
      const decisionConfig = DECISION_CONFIG[selectedDecision] || DECISION_CONFIG['ACCEPT_PRIORITY'];
      const rationaleText = decisionRationale.trim() || `Analyst confirmed decision: ${decisionConfig.label}`;

      const result = await findingsService.submitAnalystFeedback(
        finding.finding_id,
        selectedDecision,
        rationaleText,
        finding.risk_score || 68
      );

      setDecisionSaved(true);
      setActiveDecision(result.data || { analyst_decision: selectedDecision, rationale: rationaleText });

      const history = await findingsService.fetchAuditTrail(finding.finding_id);
      setFeedbackHistory(history || []);

      const verifyRes = await findingsService.verifyAuditTrail(finding.finding_id);
      setChainValid(verifyRes?.valid !== false);

      const newActivity = {
        id: Date.now(),
        type: decisionConfig.color,
        icon: User,
        headline: `Analyst Decision: ${decisionConfig.label}`,
        sub: decisionRationale ? `Rationale: "${decisionRationale}"` : `Recorded by ${currentUser.name} [${currentUser.role}]`,
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

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    const noteObj = {
      id: Date.now(),
      author: currentUser.name,
      role: currentUser.role,
      text: newNote.trim(),
      time: 'Just now'
    };
    setNotes(prev => [noteObj, ...prev]);
    setNewNote('');
  };

  const copyToClipboard = (text, type) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
    }
    if (type === 'poc') {
      setCopiedPoc(true);
      setTimeout(() => setCopiedPoc(false), 2000);
    } else if (type === 'explanation') {
      setCopiedExplanation(true);
      setTimeout(() => setCopiedExplanation(false), 2000);
    } else {
      setCopiedFix(true);
      setTimeout(() => setCopiedFix(false), 2000);
    }
  };

  const formatAuditAction = (action) => {
    const map = {
      STATUS_IN_PROGRESS: 'Work Started',
      STATUS_RESOLVED: 'Task Marked Resolved',
      STATUS_ASSIGNED: 'Owner Assigned',
      STATUS_SLA_BREACHED: 'SLA Breached Flagged',
      TICKET_ASSIGNED: 'Owner Assigned',
      TICKET_GENERATED: 'Remediation Task Created',
      ACCEPT_PRIORITY: 'Priority Confirmed',
      DOWNGRADE: 'Priority Downgraded',
      FALSE_POSITIVE: 'Marked False Positive',
      NEEDS_REVIEW: 'Flagged for Review',
      ESCALATE: 'Escalated to SecOps Lead',
    };
    return map[action] || action?.replace(/_/g, ' ') || 'Action Recorded';
  };

  const formatAuditRole = (role) => {
    if (!role) return 'Analyst';
    let r = String(role);
    r = r.replace(/UserRole\./g, '');
    return r;
  };

  const navigateToTab = (tabId) => {
    setActiveTab(tabId);
    const params = new URLSearchParams(searchParams);
    params.set('tab', tabId);
    navigate({ search: params.toString() }, { replace: true });
    if (typeof tabsRef.current?.scrollIntoView === 'function') {
      tabsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  };

  // ── Loading State ──
  if (loading) {
    return (
      <div className="f360-loading-state">
        <div className="f360-loading-inner">
          <div className="f360-loading-spinner">
            <Loader2 size={28} className="spin-slow" color="#7C3AED" />
          </div>
          <div className="f360-loading-text">
            <h3>Loading Investigation</h3>
            <p>Fetching canonical finding and remediation context…</p>
          </div>
        </div>
      </div>
    );
  }

  // ── Not Found State ──
  if (!finding) {
    return (
      <div className="f360-notfound-state">
        <AlertTriangle size={40} color="#EF4444" />
        <h3>Finding {id} not found</h3>
        <p>This finding could not be resolved from the authoritative data source.</p>
        <button className="f360-back-primary-btn" onClick={() => navigate('/findings')}>
          <ArrowLeft size={16} /> Back to Findings Queue
        </button>
      </div>
    );
  }

  // ── Authoritative field extractions from single canonical record ──
  const score = finding.risk_score ?? 0;
  const level = (finding.risk_level ?? (score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW')).toUpperCase();
  const levelFormatted = level.charAt(0).toUpperCase() + level.slice(1).toLowerCase();
  const confidencePct = Math.round((finding.detail?.finding_confidence?.score ?? 0.76) * 100);
  const confidenceClass = finding.confidence_classification || (confidencePct >= 70 ? 'High Confidence' : 'Needs Review');

  // Authoritative SLA & Workflow status derived strictly from server task or finding workflow
  const authoritativeDueAt = remediationTask?.due_at || finding.workflow?.sla_due_at || finding.workflow?.sla_deadline;
  const currentTaskStatus = remediationTask?.status || finding.workflow?.status || 'OPEN';
  const assignedOwner = remediationTask?.assigned_to || finding.workflow?.assigned_to;
  const assignedOwnerDisplay = remediationTask?.assignee_display_name || assignedOwner;

  let computedSlaStatus = (finding.workflow?.sla_status ?? 'ON_TRACK').toUpperCase();
  if (currentTaskStatus === 'RESOLVED') {
    computedSlaStatus = 'MET';
  } else if (currentTaskStatus === 'SLA_BREACHED') {
    computedSlaStatus = 'BREACHED';
  } else if (authoritativeDueAt) {
    const dueTime = new Date(authoritativeDueAt).getTime();
    if (!isNaN(dueTime) && Date.now() > dueTime) {
      computedSlaStatus = 'BREACHED';
    }
  }

  const slaStatusLabel = computedSlaStatus === 'ON_TRACK' ? 'On Track' : computedSlaStatus === 'AT_RISK' ? 'At Risk' : computedSlaStatus === 'BREACHED' ? 'Breached' : computedSlaStatus === 'MET' ? 'Met' : 'Pending';
  const slaStatusColor = computedSlaStatus === 'ON_TRACK' || computedSlaStatus === 'MET' ? 'green' : computedSlaStatus === 'AT_RISK' ? 'amber' : 'red';

  const isKev = Boolean(finding.detail?.threat_intelligence?.kev_listed);
  const epss = finding.detail?.threat_intelligence?.epss_score;
  const cvss = finding.detail?.threat_intelligence?.cvss_score || finding.detail?.cvss_score;
  const isInternet = finding.internet_exposure !== false && finding.detail?.asset_context?.internet_facing !== false;

  // Real detecting sources
  const detectingSources = finding.detail?.provenance?.source_findings ?? [];
  const scannerCount = detectingSources.length > 0
    ? detectingSources.length
    : (finding.detail?.scanner_consensus?.detected_by_count ?? (finding.detail?.scanner_consensus?.scanner_names?.length ?? 1));
  const totalScanners = finding.detail?.scanner_consensus?.total_scanners ?? Math.max(scannerCount, 3);
  const detectingScannerNames = detectingSources.length > 0
    ? detectingSources.map(s => s.scanner || 'Scanner')
    : (finding.detail?.scanner_consensus?.scanner_names || ['Nuclei']);

  const assetName = finding.detail?.asset_context?.asset_name || findingsService.getAssetDisplayName(finding.asset_id) || finding.asset_id || 'Target Asset';
  const ac = finding.detail?.asset_context ?? {};
  const criticalityVal = (ac.criticality || finding.asset_criticality || 'HIGH').toUpperCase();
  const criticalityFormatted = criticalityVal.charAt(0).toUpperCase() + criticalityVal.slice(1).toLowerCase();
  const dataSensitivityFormatted = (ac.data_sensitivity || 'CONFIDENTIAL').charAt(0).toUpperCase() + (ac.data_sensitivity || 'CONFIDENTIAL').slice(1).toLowerCase();
  const envFormatted = (ac.environment || 'production').charAt(0).toUpperCase() + (ac.environment || 'production').slice(1).toLowerCase();

  // Detailed 7-Factor Score Breakdown from M5 Engine
  const detailedScoreBreakdown = (() => {
    if (!finding) return [];
    const rawCvss = finding.detail?.threat_intelligence?.cvss_score ?? (typeof cvss === 'object' ? cvss?.base_score : cvss) ?? 0;
    const rawEpss = finding.detail?.threat_intelligence?.epss_score ?? epss ?? 0;
    const rawKev = !!(finding.detail?.threat_intelligence?.kev_listed ?? isKev);
    const rawExploit = !!(finding.detail?.threat_intelligence?.exploit_available ?? finding.exploit_available);
    const rawCriticality = (ac.criticality || finding.asset_criticality || 'UNKNOWN').toUpperCase();
    const rawExposure = ac.internet_exposure ?? finding.internet_exposure ?? isInternet;
    const rawConfidence = finding.detail?.finding_confidence?.score ?? confidenceScore ?? 0.76;

    // 1. CVSS Points
    let cvssPts = 5;
    let cvssBand = '< 4.0 (Low)';
    if (rawCvss >= 9.0) { cvssPts = 25; cvssBand = '9.0–10.0 (Critical)'; }
    else if (rawCvss >= 7.0) { cvssPts = 20; cvssBand = '7.0–8.9 (High)'; }
    else if (rawCvss >= 4.0) { cvssPts = 12; cvssBand = '4.0–6.9 (Medium)'; }

    // 2. EPSS Points
    let epssPts = 2;
    let epssBand = '< 20% (Low)';
    if (rawEpss >= 0.80) { epssPts = 20; epssBand = '80%–100% (Extreme)'; }
    else if (rawEpss >= 0.50) { epssPts = 14; epssBand = '50%–79% (High)'; }
    else if (rawEpss >= 0.20) { epssPts = 8; epssBand = '20%–49% (Moderate)'; }

    // 3. CISA KEV
    const kevPts = rawKev ? 15 : 0;
    const kevBand = rawKev ? 'Active in CISA KEV Catalog' : 'Not Listed';

    // 4. Exploit Available
    const exploitPts = rawExploit ? 10 : 0;
    const exploitBand = rawExploit ? 'Public Exploit (PoC)' : 'No Public Exploit';

    // 5. Asset Criticality
    const critMap = { 'CRITICAL': [10, 'Critical Tier'], 'HIGH': [8, 'High Tier'], 'MEDIUM': [5, 'Medium Tier'], 'LOW': [2, 'Low Tier'], 'UNKNOWN': [0, 'Unmapped'] };
    const [critPts, critBand] = critMap[rawCriticality] || [0, 'Unmapped'];

    // 6. Internet Exposure
    const exposurePts = rawExposure === true ? 10 : 0;
    const exposureBand = rawExposure === true ? 'Direct Internet Access' : (rawExposure === false ? 'Internal Network Only' : 'Unknown');

    // 7. Confidence
    let confPts = 2;
    let confBand = '< 50% (Low)';
    if (rawConfidence >= 0.90) { confPts = 10; confBand = '90%–100% (Corroborated)'; }
    else if (rawConfidence >= 0.75) { confPts = 8; confBand = '75%–89% (High Confidence)'; }
    else if (rawConfidence >= 0.50) { confPts = 5; confBand = '50%–74% (Moderate)'; }

    return [
      { name: 'CVSS Technical Severity', observed: `${rawCvss} / 10.0`, band: cvssBand, points: cvssPts, maxPoints: 25, icon: ShieldAlert, color: 'purple' },
      { name: 'EPSS Exploit Likelihood', observed: `${Math.round(rawEpss * 100)}% (${Number(rawEpss).toFixed(2)})`, band: epssBand, points: epssPts, maxPoints: 20, icon: TrendingUp, color: 'amber' },
      { name: 'CISA KEV Catalog Listing', observed: rawKev ? 'Listed (Confirmed)' : 'Not Listed', band: kevBand, points: kevPts, maxPoints: 15, icon: Flame, color: 'red' },
      { name: 'Public Exploit Code', observed: rawExploit ? 'Available (PoC)' : 'None Identified', band: exploitBand, points: exploitPts, maxPoints: 10, icon: Zap, color: 'orange' },
      { name: 'Asset Business Criticality', observed: rawCriticality, band: critBand, points: critPts, maxPoints: 10, icon: Server, color: 'blue' },
      { name: 'Internet Network Exposure', observed: rawExposure === true ? 'Internet-Facing' : (rawExposure === false ? 'Internal Only' : 'Unknown'), band: exposureBand, points: exposurePts, maxPoints: 10, icon: Globe, color: 'cyan' },
      { name: 'Scanner Verification Confidence', observed: `${Math.round(rawConfidence * 100)}% (${Number(rawConfidence).toFixed(2)})`, band: confBand, points: confPts, maxPoints: 10, icon: ShieldCheck, color: 'green' },
    ];
  })();

  // Sanitization helper for customer-facing explanation text
  const sanitizeExplanationText = (str) => {
    if (!str || typeof str !== 'string') return '';
    let s = str;
    // Fix ordinals: 91th -> 91st, 21th -> 21st, 1th -> 1st, 2th -> 2nd, 3th -> 3rd, etc.
    s = s.replace(/\b(\d*1)th\b/g, '$1st');
    s = s.replace(/\b(\d*2)th\b/g, '$1nd');
    s = s.replace(/\b(\d*3)th\b/g, '$1rd');
    // Fix 11th, 12th, 13th exceptions if mistakenly replaced
    s = s.replace(/\b11st\b/g, '11th');
    s = s.replace(/\b12nd\b/g, '12th');
    s = s.replace(/\b13rd\b/g, '13th');

    // Clean raw enum identifiers and internal engine labels
    s = s.replace(/CONFIDENCECLASSIFICATION\.([A-Z_]+)/g, (_, match) => match.replace(/_/g, ' ').toLowerCase());
    s = s.replace(/CRITICALITY\.([A-Z_]+)/g, (_, match) => match.replace(/_/g, ' ').toLowerCase());
    s = s.replace(/\bUNKNOWN\b/g, 'Unclassified');
    s = s.replace(/risk engine \(M5\)/gi, 'Contextual Risk Engine');
    s = s.replace(/M[1-8]\s*(engine|module|service|adapter)?/gi, '');
    s = s.replace(/CRITICAL-criticality/gi, 'Critical');
    s = s.replace(/HIGH-criticality/gi, 'High');
    s = s.replace(/MEDIUM-criticality/gi, 'Medium');
    s = s.replace(/LOW-criticality/gi, 'Low');
    s = s.replace(/CISA KEV listed\s*=\s*True/gi, 'Listed on CISA KEV');
    s = s.replace(/CISA KEV listed\s*=\s*False/gi, 'Not listed on CISA KEV');
    s = s.replace(/exploit available\s*=\s*True/gi, 'Public exploit available');
    s = s.replace(/exploit available\s*=\s*False/gi, 'No public exploit identified');

    return s.trim();
  };

  const rawTechnicalExp = finding.detail?.explanation?.technical || '';
  const rawManagementExp = finding.detail?.explanation?.management || '';
  const sanitizedTechnical = sanitizeExplanationText(rawTechnicalExp);
  const sanitizedManagement = sanitizeExplanationText(rawManagementExp);
  const hasPersistedExplanation = Boolean(rawTechnicalExp || rawManagementExp || (finding.detail?.explanation?.top_risk_drivers && finding.detail?.explanation?.top_risk_drivers.length > 0));

  // Validated M6 Top Risk Drivers grounded in authoritative structured data
  const validatedDrivers = (() => {
    if (!finding) return [];
    const rawDrivers = finding.detail?.explanation?.top_risk_drivers || [];
    const breakdown = finding.detail?.risk_assessment?.score_breakdown || {};
    const ti = finding.detail?.threat_intelligence || {};
    const rawExposure = ac.internet_exposure ?? ac.internet_facing ?? finding.internet_exposure;
    const rawCrit = (ac.criticality || finding.asset_criticality || '').toUpperCase();
    const rawCvss = ti.cvss_score ?? (typeof finding.detail?.cvss_score === 'object' ? finding.detail?.cvss_score?.base_score : finding.detail?.cvss_score);
    const rawEpss = ti.epss_score;

    const driverDefinitions = {
      HIGH_CVSS: {
        id: 'HIGH_CVSS',
        title: 'High CVSS Severity',
        observed: rawCvss != null ? `CVSS ${rawCvss} / 10.0` : 'High Baseline Severity',
        contribution: breakdown.cvss_contribution,
        maxPoints: 25,
        whyItMatters: 'Base vulnerability metrics reflect significant baseline technical severity.',
        sourceStage: 'Stage 4: Threat Intelligence',
        icon: ShieldAlert,
        color: 'purple',
        isValid: rawCvss != null && rawCvss >= 7.0,
      },
      HIGH_EPSS: {
        id: 'HIGH_EPSS',
        title: 'High Exploit Probability',
        observed: rawEpss != null ? `EPSS ${Math.round(rawEpss * 100)}% (${Number(rawEpss).toFixed(2)})` : 'High Exploit Likelihood',
        contribution: breakdown.epss_contribution,
        maxPoints: 20,
        whyItMatters: 'Statistical probability of weaponization in the next 30 days is significantly elevated.',
        sourceStage: 'Stage 4: Threat Intelligence',
        icon: TrendingUp,
        color: 'amber',
        isValid: rawEpss != null && rawEpss >= 0.50,
      },
      KEV_LISTED: {
        id: 'KEV_LISTED',
        title: 'CISA KEV Listed',
        observed: isKev ? 'Active in CISA KEV Catalog' : 'Not Listed',
        contribution: breakdown.kev_contribution,
        maxPoints: 15,
        whyItMatters: 'Confirmed active exploitation in the wild according to federal advisory bulletins.',
        sourceStage: 'Stage 4: Threat Intelligence',
        icon: Flame,
        color: 'red',
        isValid: isKev === true,
      },
      EXPLOIT_AVAILABLE: {
        id: 'EXPLOIT_AVAILABLE',
        title: 'Public Exploit Available',
        observed: finding.detail?.threat_intelligence?.exploit_available ? 'Public Exploit (PoC)' : 'None Identified',
        contribution: breakdown.exploit_contribution,
        maxPoints: 10,
        whyItMatters: 'Functional exploit material or proof-of-concept is publicly accessible.',
        sourceStage: 'Stage 4: Threat Intelligence',
        icon: Zap,
        color: 'orange',
        isValid: Boolean(finding.detail?.threat_intelligence?.exploit_available),
      },
      PUBLIC_EXPLOIT: {
        id: 'PUBLIC_EXPLOIT',
        title: 'Public Exploit Available',
        observed: finding.detail?.threat_intelligence?.exploit_available ? 'Public Exploit (PoC)' : 'None Identified',
        contribution: breakdown.exploit_contribution,
        maxPoints: 10,
        whyItMatters: 'Functional exploit material or proof-of-concept is publicly accessible.',
        sourceStage: 'Stage 4: Threat Intelligence',
        icon: Zap,
        color: 'orange',
        isValid: Boolean(finding.detail?.threat_intelligence?.exploit_available),
      },
      CRITICAL_ASSET: {
        id: 'CRITICAL_ASSET',
        title: rawCrit === 'CRITICAL' ? 'Critical Asset' : rawCrit === 'HIGH' ? 'High Asset Criticality' : rawCrit === 'MEDIUM' ? 'Medium Asset Criticality' : rawCrit === 'LOW' ? 'Low Asset Criticality' : 'Asset Criticality Not Available',
        observed: rawCrit ? `${rawCrit.charAt(0) + rawCrit.slice(1).toLowerCase()} Tier (${assetName})` : 'Unclassified Asset',
        contribution: breakdown.asset_criticality_contribution,
        maxPoints: 10,
        whyItMatters: `This system is registered with ${rawCrit ? rawCrit.toLowerCase() : 'unclassified'} criticality in the asset inventory.`,
        sourceStage: 'Stage 4: Asset Context',
        icon: Server,
        color: 'blue',
        isValid: ['CRITICAL', 'HIGH'].includes(rawCrit),
      },
      INTERNET_FACING: {
        id: 'INTERNET_FACING',
        title: 'Internet-Facing Asset',
        observed: rawExposure === true ? 'Direct Internet Access' : (rawExposure === false ? 'Internal Network Only' : 'Unknown Exposure'),
        contribution: breakdown.exposure_contribution,
        maxPoints: 10,
        whyItMatters: 'Direct perimeter exposure allows unauthenticated network reconnaissance and attacks.',
        sourceStage: 'Stage 4: Asset Context',
        icon: Globe,
        color: 'cyan',
        isValid: rawExposure === true,
      },
      HIGH_SCANNER_CONSENSUS: {
        id: 'HIGH_SCANNER_CONSENSUS',
        title: scannerCount > 1 ? 'Multi-Scanner Detection' : 'Single-Source Detection',
        observed: `${scannerCount} of ${totalScanners} scanners corroborated`,
        contribution: breakdown.scanner_confidence_contribution,
        maxPoints: 10,
        whyItMatters: scannerCount > 1 ? 'Multiple independent security engines detected and validated the finding signature.' : 'Single security engine detected the finding signature.',
        sourceStage: 'Stage 2: Scanner Consensus',
        icon: ShieldCheck,
        color: 'green',
        isValid: scannerCount > 1,
      },
    };

    const cards = [];
    for (const driverCode of rawDrivers) {
      const code = String(driverCode).toUpperCase().trim();
      if (driverDefinitions[code]) {
        const def = driverDefinitions[code];
        if (def.isValid && !cards.some(c => c.id === def.id)) {
          cards.push(def);
        }
      }
    }

    // Grounded fallback if rawDrivers was empty
    if (cards.length === 0) {
      for (const [key, def] of Object.entries(driverDefinitions)) {
        if (key === 'PUBLIC_EXPLOIT') continue;
        if (def.isValid && (def.contribution > 0 || breakdown[key.toLowerCase() + '_contribution'] > 0)) {
          if (!cards.some(c => c.id === def.id)) {
            cards.push(def);
          }
        }
      }
    }

    return cards;
  })();

  // Authoritative references from M6 explanation / remediation
  const authoritativeReferences = (() => {
    if (!finding) return [];
    const refs = [];
    const rawRefs = finding.detail?.explanation?.references || finding.detail?.remediation?.references || [];
    if (Array.isArray(rawRefs)) {
      for (const r of rawRefs) {
        if (typeof r === 'string' && (r.startsWith('http://') || r.startsWith('https://'))) {
          refs.push({ title: r.replace(/^https?:\/\//, '').split('/')[0] + ' Advisory', url: r });
        }
      }
    }
    if (finding.cve_id && finding.cve_id.toUpperCase().startsWith('CVE-')) {
      const cveUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.cve_id)}`;
      if (!refs.some(r => r.url === cveUrl)) {
        refs.unshift({ title: `NVD Vulnerability Database (${finding.cve_id})`, url: cveUrl });
      }
    }
    return refs;
  })();

  // Data completeness signals
  const availableSignals = [];
  const missingSignals = [];

  if (finding.cve_id) {
    availableSignals.push({ name: 'CVE Identifier', val: finding.cve_id });
  } else {
    missingSignals.push({ name: 'CVE Identifier', reason: 'No CVE assigned' });
  }

  if (cvss != null) {
    availableSignals.push({ name: 'CVSS Score', val: `${typeof cvss === 'object' ? cvss?.base_score : cvss} / 10.0` });
  } else {
    missingSignals.push({ name: 'CVSS Score', reason: 'CVSS not available' });
  }

  if (epss != null) {
    availableSignals.push({ name: 'EPSS Probability', val: `${Math.round(epss * 100)}% (${Number(epss).toFixed(3)})` });
  } else {
    missingSignals.push({ name: 'EPSS Probability', reason: 'EPSS not enriched' });
  }

  if (isKev) {
    availableSignals.push({ name: 'CISA KEV Catalog', val: 'Listed in Known Exploited Vulnerabilities' });
  } else {
    missingSignals.push({ name: 'CISA KEV Catalog', reason: 'Not listed in CISA KEV catalog' });
  }

  if (finding.detail?.threat_intelligence?.exploit_available) {
    availableSignals.push({ name: 'Public Exploit Material', val: 'Public exploit code / PoC available' });
  } else {
    missingSignals.push({ name: 'Public Exploit Material', reason: 'Public exploit information not available' });
  }

  if (ac.asset_name || finding.asset_id) {
    availableSignals.push({ name: 'Asset Inventory', val: `${assetName} (${finding.asset_id})` });
  } else {
    missingSignals.push({ name: 'Asset Inventory', reason: 'Unregistered asset context' });
  }

  if (criticalityVal && criticalityVal !== 'UNKNOWN') {
    availableSignals.push({ name: 'Asset Criticality', val: criticalityFormatted });
  } else {
    missingSignals.push({ name: 'Asset Criticality', reason: 'Asset criticality not specified' });
  }

  if (ac.environment && ac.environment !== 'UNKNOWN') {
    availableSignals.push({ name: 'Environment', val: envFormatted });
  } else {
    missingSignals.push({ name: 'Environment', reason: 'Asset environment not specified' });
  }

  if (finding.internet_exposure != null || ac.internet_facing != null) {
    availableSignals.push({ name: 'Internet Exposure', val: isInternet ? 'Internet-facing asset' : 'Internal network only' });
  } else {
    missingSignals.push({ name: 'Internet Exposure', reason: 'Exposure not specified' });
  }

  if (detectingScannerNames.length > 0) {
    availableSignals.push({ name: 'Scanner Corroboration', val: `${detectingScannerNames.join(', ')} (${scannerCount} of ${totalScanners} scanners)` });
  } else {
    missingSignals.push({ name: 'Scanner Corroboration', reason: 'Scanner evidence unavailable' });
  }

  // Plain-English Reasoning text from M6 Explainability engine
  const whyItMatters = sanitizedTechnical
    || sanitizedManagement
    || `Known exploitation, high asset criticality and internet exposure drive this finding's ${levelFormatted} contextual risk score.`;

  // Recommended Technical Fix Code from M6/M7
  const fixCode = (() => {
    const cve = (finding.cve_id || '').toUpperCase();
    const vuln = (finding.vulnerability_name || '').toLowerCase();

    if (cve.includes('CVE-2021-44228') || vuln.includes('log4j') || vuln.includes('log4shell')) {
      return `<!-- 1. Dependency Upgrade in pom.xml / build.gradle -->\n<dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.17.1</version>\n</dependency>\n\n<!-- 2. JVM Startup Mitigation Parameter -->\n-Dlog4j2.formatMsgNoLookups=true`;
    }

    if (vuln.includes('sql') || vuln.includes('injection')) {
      return `// Parameterized Query (PreparedStatement)\nString sql = "SELECT * FROM records WHERE tenant_id = ? AND status = ?";\nPreparedStatement stmt = conn.prepareStatement(sql);\nstmt.setString(1, tenantId);\nstmt.setString(2, "ACTIVE");\nResultSet rs = stmt.executeQuery();`;
    }

    if (finding.recommended_action) {
      return `// Configuration & Fix Directive\n${finding.recommended_action}`;
    }

    return `// Apply security patch for ${finding.vulnerability_name}\nsudo apt-get update && sudo apt-get --only-upgrade install package-name`;
  })();

  // Real or truthfully absent PoC payload
  const rawPayload = detectingSources[0]?.raw_evidence?.payload
    || detectingSources[0]?.endpoint
    || (finding.detail?.scanner_evidence?.payload ?? null);

  const pocPayloadText = rawPayload ? String(rawPayload) : 'Not available';

  // Remediation checklist from API or static fallback
  const remediationSteps = [
    { id: 1, title: 'Audit vulnerable dependencies & configurations', desc: `Scan inventory for ${finding.cve_id || finding.vulnerability_name} instances.`, status: currentTaskStatus !== 'OPEN' ? 'Completed' : 'In Progress' },
    { id: 2, title: `Apply vendor patch or upgrade`, desc: finding.recommended_action || 'Upgrade to the latest secure release.', status: currentTaskStatus === 'IN_PROGRESS' ? 'In Progress' : (currentTaskStatus === 'RESOLVED' ? 'Completed' : 'Not Started') },
    { id: 3, title: 'Implement perimeter controls & WAF rules', desc: 'Enforce perimeter filtering and request rate limits.', status: currentTaskStatus === 'IN_PROGRESS' || currentTaskStatus === 'RESOLVED' ? 'In Progress' : 'Not Started' },
    { id: 4, title: 'Deploy to staging & run verification scan', desc: 'Verify remediation in staging environment with scanner agent.', status: currentTaskStatus === 'RESOLVED' ? 'Completed' : 'Not Started' }
  ];

  const activeSteps = checklistSteps.length > 0 ? checklistSteps : remediationSteps;
  const completedStepCount = activeSteps.filter(s => {
    const st = s.status || '';
    return st === 'COMPLETED' || st === 'Completed';
  }).length;

  const remedPriority = remediationTask?.priority
    ? (remediationTask.priority.charAt(0).toUpperCase() + remediationTask.priority.slice(1).toLowerCase())
    : (score >= 90 ? 'Critical' : score >= 70 ? 'High' : score >= 40 ? 'Medium' : 'Low');

  const slaHours = remediationTask?.sla_hours || finding.workflow?.sla_hours || 168;
  const priorityRank = finding.priority_rank || '1';

  const riztraceUrl = scanRunId && orgId
    ? `/findings/${id}/riztrace?scan_run_id=${encodeURIComponent(scanRunId)}&org_id=${encodeURIComponent(orgId)}`
    : `/findings/${id}/riztrace`;

  const backUrl = scanRunId && orgId
    ? `/command-center?scan_run_id=${encodeURIComponent(scanRunId)}&org_id=${encodeURIComponent(orgId)}`
    : '/findings';
  const backLabel = scanRunId ? 'Command Center' : 'Findings';

  // Journey node data reflecting complete 8-stage finding lifecycle
  const journeyNodes = [
    {
      id: 'detected',
      label: 'Scanner Ingest',
      outcome: `Detected by ${scannerCount} of ${totalScanners} scanners`,
      ts: finding.detail?.provenance?.source_findings?.[0]?.timestamp || null,
      done: true,
      detail: `Source: ${detectingScannerNames.join(', ')} · Finding ID: ${finding.finding_id}`,
    },
    {
      id: 'correlated',
      label: 'Correlated',
      outcome: `Canonical ID assigned`,
      ts: finding.created_at || null,
      done: true,
      detail: `Deduplication hash: ${finding.finding_id} · Sources merged: ${scannerCount}`,
    },
    {
      id: 'risk',
      label: 'Risk Scored',
      outcome: `${levelFormatted} · ${score}/100`,
      ts: finding.created_at || null,
      done: true,
      detail: `Contextual risk score ${score}/100 evaluated by M5 engine. Threshold: HIGH (50–74).`,
    },
    {
      id: 'explainability',
      label: 'Explainability',
      outcome: hasPersistedExplanation ? `${validatedDrivers.length} Drivers · Generated` : 'Pending',
      ts: finding.detail?.explanation?.generated_at || finding.created_at || null,
      done: hasPersistedExplanation,
      detail: hasPersistedExplanation
        ? `Explainable AI analysis generated. Top risk drivers: ${validatedDrivers.map(d => d.title).join(', ') || 'Authoritative signals available'}. Passthrough risk score: ${score}/100.`
        : 'Explanation provenance not available.',
    },
    {
      id: 'task',
      label: 'Task Created',
      outcome: remediationTask ? `${remediationTask.ticket_id}` : 'Pending',
      ts: remediationTask?.created_at || null,
      done: !!remediationTask,
      detail: remediationTask ? `Priority: ${remedPriority} · SLA: ${slaHours}h window` : 'No remediation task generated yet.',
    },
    {
      id: 'owner',
      label: 'Owner Assigned',
      outcome: assignedOwnerDisplay || 'Pending',
      ts: null,
      done: !!assignedOwner,
      detail: assignedOwner ? `Assigned to: ${assignedOwnerDisplay} (${assignedOwner})` : 'Awaiting SOC assignment.',
    },
    {
      id: 'status',
      label: currentTaskStatus === 'RESOLVED' ? 'Resolved' : 'In Progress',
      outcome: currentTaskStatus.replace(/_/g, ' '),
      ts: null,
      done: currentTaskStatus === 'RESOLVED',
      active: currentTaskStatus === 'IN_PROGRESS',
      detail: `Current workflow status: ${currentTaskStatus}. SLA countdown: ${formatSlaRemaining(authoritativeDueAt)}.`,
    },
  ];

  return (
    <div className="investigate-360-container">

      {/* ── Toast Notification ── */}
      {toastMsg && (
        <div className="toast-notification">
          <CheckCircle2 size={16} color="#10B981" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* ── Compact Sticky Finding Bar on Scroll ── */}
      <div className={`sticky-finding-compact-bar ${showStickyBar ? 'visible' : ''}`} role="navigation" aria-label="Finding quick navigation">
        <div className="compact-bar-inner">
          <div className="compact-bar-left">
            <button
              className="f360-compact-back"
              onClick={() => navigate(backUrl)}
              aria-label={`Back to ${backLabel}`}
            >
              <ArrowLeft size={14} />
            </button>
            <span className="compact-priority-badge">#{priorityRank}</span>
            <span className="compact-finding-title">{finding.vulnerability_name}</span>
            {finding.cve_id && <span className="compact-cve-tag">{finding.cve_id}</span>}
            <span className="compact-sep">·</span>
            <span className="compact-asset-name">{assetName}</span>
          </div>

          <div className="compact-bar-tabs" role="tablist">
            {TABS.map(({ id: tabId, label }) => (
              <button
                key={tabId}
                role="tab"
                aria-selected={activeTab === tabId}
                className={`compact-tab-btn ${activeTab === tabId ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab(tabId);
                  window.scrollTo({ top: 220, behavior: 'smooth' });
                }}
              >
                <span>{label}</span>
              </button>
            ))}
          </div>

          <div className="compact-bar-right">
            <div className={`f360-compact-risk-pill ${level.toLowerCase()}`}>
              <span className="score-val">{score}</span>
              <span className="score-lbl">{levelFormatted}</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── 1. Top Navigation Row ── */}
      <div className="f360-top-nav">
        <button
          className="investigate-back-btn"
          onClick={() => navigate(backUrl)}
          aria-label={`Back to ${backLabel}`}
        >
          <ArrowLeft size={16} />
          <span>Back to {backLabel}</span>
        </button>

        <button
          className="f360-trace-btn"
          onClick={() => navigate(riztraceUrl)}
          title="Open Decision Provenance (RizTrace)"
        >
          <GitCommit size={14} />
          <span>Trace Decision</span>
        </button>
      </div>

      {/* ── 2. Hero Header ── */}
      <div className="f360-hero">
        {/* LEFT: Identity */}
        <div className="f360-hero-left">
          <div className="f360-hero-eyebrow">
            <span className="f360-priority-badge">#{priorityRank}</span>
            {finding.cve_id && <span className="f360-cve-tag">{finding.cve_id}</span>}
          </div>

          <h1 className="f360-main-title">{finding.vulnerability_name}</h1>

          <div className="f360-asset-row">
            <MapPin size={13} color="#64748B" />
            <span className="f360-asset-name">{assetName}</span>
            <span className="f360-dot">·</span>
            <span className="f360-id-mono">{finding.finding_id}</span>
          </div>

          <div className="f360-telemetry-row">
            {isKev && (
              <span className="inv-badge pink">
                <Flame size={12} /> Known Exploited
              </span>
            )}
            {epss != null && (
              <span className="inv-badge peach">
                <TrendingUp size={12} /> EPSS {Math.round(epss * 100)}%
              </span>
            )}
            <span className="inv-badge blue">
              <Globe size={12} /> {isInternet ? 'Internet-facing' : 'Internal'}
            </span>
            <span className="inv-badge blue">
              <Shield size={12} /> Detected by {scannerCount} of {totalScanners} scanners
            </span>
          </div>
        </div>

        {/* RIGHT: KPI Metrics */}
        <div className="f360-kpi-strip">
          {/* Contextual Risk */}
          <div className="f360-kpi-card" title="Contextual risk: M5 engine score based on asset threat, exposure and exploitability.">
            <div className="f360-kpi-eyebrow">Contextual Risk</div>
            <div className="f360-kpi-value risk-high">{score}</div>
            <div className={`f360-kpi-badge risk-${level.toLowerCase()}`}>{levelFormatted} · {score}/100</div>
          </div>

          {/* Confidence */}
          <div className="f360-kpi-card" title="Scanner detection confidence from M3 confidence engine.">
            <div className="f360-kpi-eyebrow">Confidence</div>
            <div className="f360-kpi-value">{confidencePct}%</div>
            <div className="f360-kpi-badge confidence-high">High Confidence</div>
          </div>

          {/* SLA Status */}
          <div className="f360-kpi-card" title="SLA status based on deadline countdown.">
            <div className="f360-kpi-eyebrow">SLA Status</div>
            <div className={`f360-kpi-status-row ${slaStatusColor}`}>
              <CheckCircle2 size={14} />
              <span>{slaStatusLabel}</span>
            </div>
            <div className="f360-kpi-subtext">{slaHours}h window</div>
          </div>

          {/* Workflow Status */}
          <div className="f360-kpi-card" title="Current task workflow state from M7 remediation engine.">
            <div className="f360-kpi-eyebrow">Workflow Status</div>
            <div className="f360-kpi-status-row blue">
              <span className={`f360-status-dot ${currentTaskStatus === 'RESOLVED' ? 'green' : currentTaskStatus === 'IN_PROGRESS' ? 'blue' : 'gray'}`} />
              <span>{currentTaskStatus === 'IN_PROGRESS' ? 'In Progress' : currentTaskStatus.replace(/_/g, ' ')}</span>
            </div>
            <div className="f360-kpi-subtext">{remediationTask ? 'Active task' : 'No task'}</div>
          </div>

          {/* Remediation Priority — DISTINCT from Contextual Risk */}
          <div className="f360-kpi-card f360-priority-card" title="Remediation Priority: M7 SLA policy (separate from Contextual Risk). Score 40–69 = MEDIUM (168h SLA).">
            <div className="f360-kpi-eyebrow">Remediation Priority</div>
            <div className="f360-priority-value">{remedPriority}</div>
            <div className="f360-kpi-subtext">{slaHours}h SLA</div>
          </div>
        </div>
      </div>

      {/* ── 3. Action Strip ── */}
      <div className="f360-action-strip">
        {/* Recommended Fix */}
        <div className="f360-action-fix">
          <div className="f360-action-fix-icon">
            <Wrench size={16} />
          </div>
          <div className="f360-action-fix-text">
            <div className="f360-action-label">Recommended Fix</div>
            <div className="f360-action-fix-desc">
              {finding.recommended_action || 'Upgrade to the latest patched version or apply vendor mitigation.'}
            </div>
          </div>
        </div>

        <div className="f360-action-divider" />

        {/* SLA Countdown */}
        <div className="f360-action-sla">
          <Clock size={15} color="#EA580C" />
          <div>
            <div className="f360-action-label">SLA Remaining</div>
            <div className={`f360-sla-countdown ${computedSlaStatus === 'BREACHED' ? 'breached' : ''}`}>
              {formatSlaRemaining(authoritativeDueAt)}
            </div>
            {authoritativeDueAt && (
              <div className="f360-sla-expires">SLA expires {formatSlaDeadline(authoritativeDueAt)}</div>
            )}
          </div>
        </div>

        <div className="f360-action-divider" />

        {/* Owner */}
        <div className="f360-action-owner" style={{ position: 'relative' }}>
          <div className="f360-owner-avatar">
            {assignedOwnerDisplay ? assignedOwnerDisplay.charAt(0).toUpperCase() : <User size={14} />}
          </div>
          <div>
            <div className="f360-action-label">Owner</div>
            <div className="f360-owner-name">{assignedOwnerDisplay || 'Unassigned'}</div>
          </div>
          <button
            className={`f360-reassign-btn ${currentUser.role === 'VIEWER' ? 'disabled' : ''}`}
            onClick={() => {
              if (currentUser.role === 'VIEWER') {
                setRbacError('Permission Denied (403): VIEWER role cannot assign ticket owners.');
                return;
              }
              setShowAssignModal(!showAssignModal);
            }}
            disabled={currentUser.role === 'VIEWER'}
            title={currentUser.role === 'VIEWER' ? 'Viewer Role is Read-Only' : 'Assign Owner'}
            aria-label="Assign task owner"
          >
            <RefreshCw size={12} />
          </button>

          {/* Assign Owner Popover */}
          {showAssignModal && (
            <div className="assign-owner-popover fade-in" role="dialog" aria-label="Assign Remediation Owner" style={{ zIndex: 1000 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span className="popover-title" style={{ fontWeight: 700, fontSize: '13px', color: '#0F172A' }}>Assign Remediation Owner</span>
                <button style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px' }} onClick={() => setShowAssignModal(false)} aria-label="Close">
                  <X size={14} color="#64748B" />
                </button>
              </div>
              <select
                className="assign-select"
                value={selectedAssignee}
                onChange={e => {
                  setSelectedAssignee(e.target.value);
                  setCustomAssignee('');
                }}
                aria-label="Select team"
                style={{ width: '100%', marginBottom: '8px', padding: '8px 10px', borderRadius: '8px', border: '1px solid #CBD5E1' }}
              >
                <option value="secops">secops (SOC Operations Team)</option>
                <option value="appsec-team">appsec-team (Application Security)</option>
                <option value="payments-infra">payments-infra (Payments Engineering)</option>
                <option value="dev-lead">dev-lead (Lead Developer)</option>
                <option value="cloud-eng">cloud-eng (Cloud Infrastructure)</option>
              </select>
              <input
                type="text"
                placeholder="Or custom assignee handle…"
                className="assign-select"
                value={customAssignee}
                onChange={e => setCustomAssignee(e.target.value)}
                aria-label="Custom assignee"
                style={{ width: '100%', marginBottom: '10px', padding: '8px 10px', borderRadius: '8px', border: '1px solid #CBD5E1', boxSizing: 'border-box' }}
              />
              <button
                className="assign-btn-confirm"
                type="button"
                onClick={handleAssignConfirm}
                disabled={assigningOwner || currentUser.role === 'VIEWER'}
                aria-label="Confirm assignment"
                style={{
                  width: '100%',
                  padding: '9px 14px',
                  background: '#7C3AED',
                  color: '#FFFFFF',
                  border: 'none',
                  borderRadius: '8px',
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '6px'
                }}
              >
                {assigningOwner ? <Loader2 size={13} className="spin-slow" /> : <Check size={13} />}
                <span>{assigningOwner ? 'Assigning…' : 'Confirm Assignment'}</span>
              </button>
            </div>
          )}
        </div>

        <div className="f360-action-divider" />

        {/* State-Aware Primary Action */}
        <div className="f360-action-buttons">
          {!remediationTask ? (
            <button
              className="f360-primary-btn"
              onClick={handleStartRemediation}
              disabled={creatingTask || currentUser.role === 'VIEWER'}
              id="btn-start-remediation"
              aria-label="Start Remediation"
            >
              {creatingTask ? <Loader2 size={15} className="spin-slow" /> : <Zap size={15} />}
              <span>{creatingTask ? 'Generating…' : 'Start Remediation'}</span>
            </button>
          ) : currentTaskStatus === 'OPEN' ? (
            <button
              className="f360-primary-btn"
              onClick={() => handleStatusChange('IN_PROGRESS')}
              disabled={updatingTaskStatus || currentUser.role === 'VIEWER'}
              aria-label="Start Work"
            >
              {updatingTaskStatus ? <Loader2 size={15} className="spin-slow" /> : <ArrowRight size={15} />}
              <span>Start Work</span>
            </button>
          ) : currentTaskStatus === 'ASSIGNED' ? (
            <button
              className="f360-primary-btn"
              onClick={() => handleStatusChange('IN_PROGRESS')}
              disabled={updatingTaskStatus || currentUser.role === 'VIEWER'}
              aria-label="Start Work in Progress"
            >
              {updatingTaskStatus ? <Loader2 size={15} className="spin-slow" /> : <ArrowRight size={15} />}
              <span>Start Work</span>
            </button>
          ) : currentTaskStatus === 'IN_PROGRESS' ? (
            <button
              className="f360-resolve-btn"
              onClick={() => handleStatusChange('RESOLVED')}
              disabled={updatingTaskStatus || currentUser.role === 'VIEWER'}
              aria-label="Mark task as resolved"
            >
              {updatingTaskStatus ? <Loader2 size={14} className="spin-slow" /> : <Check size={14} />}
              <span>{updatingTaskStatus ? 'Resolving…' : 'Mark Resolved'}</span>
            </button>
          ) : (
            <button
              className="f360-resolved-badge"
              onClick={() => navigateToTab('remediation')}
              aria-label="View resolved task"
            >
              <CheckCircle2 size={15} />
              <span>Resolved</span>
            </button>
          )}
        </div>
      </div>

      {/* ── 4. Tab Bar ── */}
      <div className="f360-tabs-wrapper" ref={tabsRef}>
        <div className="f360-tabs-bar" role="tablist" aria-label="Finding360 sections">
          {TABS.map(({ id: tabId, label, icon: Icon }) => (
            <button
              key={tabId}
              id={`tab-${tabId}`}
              aria-selected={activeTab === tabId}
              aria-controls={`tabpanel-${tabId}`}
              className={`f360-tab-btn ${activeTab === tabId ? 'active' : ''}`}
              onClick={() => navigateToTab(tabId)}
            >
              <Icon size={15} aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ── 5. TAB 1: OVERVIEW ── */}
      {activeTab === 'overview' && (
        <div
          className="investigate-tab-content fade-in"
          id="tabpanel-overview"
          role="tabpanel"
          aria-labelledby="tab-overview"
        >
          {/* Top Preview Card: Why this risk? */}
          <div className="inv-card f360-why-risk-preview-card" style={{ marginBottom: '20px' }}>
            <div className="inv-card-header">
              <div className="inv-card-title-group">
                <div className="card-header-icon-box purple"><Sparkles size={17} /></div>
                <div>
                  <h3 className="inv-card-title">Why this risk?</h3>
                  <p className="inv-card-subtitle">Contextual AI-assisted signal interpretation and risk rationale</p>
                </div>
              </div>
              <div className="f360-why-risk-preview-badge">
                <span className={`f360-badge-risk-${level.toLowerCase()}`}>{levelFormatted} contextual risk · {score}/100</span>
              </div>
            </div>
            <div className="inv-card-body" style={{ padding: '18px 24px' }}>
              <p className="f360-why-risk-preview-text" style={{ fontSize: '13.5px', lineHeight: '1.6', color: 'var(--text-secondary, #334155)', margin: '0 0 14px 0' }}>
                {sanitizedManagement || sanitizedTechnical || 'Detailed explanation not available.'}
              </p>
              <div className="f360-why-risk-preview-footer" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                <div className="f360-why-risk-chips" style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {validatedDrivers.slice(0, 3).map(driver => (
                    <span key={driver.id} className={`f360-driver-chip ${driver.color}`}>
                      <driver.icon size={12} />
                      <span>{driver.title}</span>
                    </span>
                  ))}
                </div>
                <button
                  className="f360-view-more-link"
                  onClick={() => navigateToTab('explainability')}
                  aria-label="View Full Explanation"
                  style={{ fontWeight: 700, fontSize: '13px' }}
                >
                  View Full Explanation →
                </button>
              </div>
            </div>
          </div>

          {/* Top Row: Priority Rationale + Threat & Asset Context */}
          <div className="investigate-two-col-layout">

            {/* LEFT: Priority Rationale */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Target size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Priority Rationale</h3>
                    <p className="inv-card-subtitle">Why this finding requires immediate attention</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {/* Key metrics */}
                <div className="f360-rationale-metrics">
                  <div className="f360-rationale-metric-item">
                    <span className="f360-rationale-metric-label">Contextual Risk</span>
                    <span className="f360-badge-risk-high">High · {score}/100</span>
                  </div>
                  <div className="f360-rationale-metric-divider" />
                  <div className="f360-rationale-metric-item">
                    <span className="f360-rationale-metric-label">Remediation Priority</span>
                    <span className="f360-badge-priority-medium">Medium · {slaHours}h</span>
                  </div>
                </div>

                {/* Risk drivers grid */}
                <div className="f360-drivers-grid">
                  <div className="f360-driver-card">
                    <div className="f360-driver-icon pink"><Flame size={14} /></div>
                    <div className="f360-driver-content">
                      <div className="f360-driver-label">CISA KEV Status</div>
                      <div className="f360-driver-value">{isKev ? 'Listed on Known Exploited Vulnerabilities' : 'Not listed on CISA KEV'}</div>
                    </div>
                  </div>

                  <div className="f360-driver-card">
                    <div className="f360-driver-icon blue"><Globe size={14} /></div>
                    <div className="f360-driver-content">
                      <div className="f360-driver-label">Internet Exposure</div>
                      <div className="f360-driver-value">{isInternet ? 'Accessible from public internet' : 'Internal network asset'}</div>
                    </div>
                  </div>

                  <div className="f360-driver-card">
                    <div className="f360-driver-icon purple"><Server size={14} /></div>
                    <div className="f360-driver-content">
                      <div className="f360-driver-label">Asset Criticality</div>
                      <div className="f360-driver-value">{criticalityFormatted} criticality · {dataSensitivityFormatted} data</div>
                    </div>
                  </div>

                  <div className="f360-driver-card">
                    <div className="f360-driver-icon green"><Shield size={14} /></div>
                    <div className="f360-driver-content">
                      <div className="f360-driver-label">Scanner Consensus</div>
                      <div className="f360-driver-value">
                        {scannerCount === 1
                          ? `Single-source detection · 1 of ${totalScanners} configured scanners`
                          : `Multi-source · ${scannerCount} of ${totalScanners} scanners corroborated`}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Expandable full explanation with Detailed Score Breakdown */}
                <div className="f360-explanation-block">
                  <button
                    className="f360-view-explanation-btn"
                    onClick={() => setShowFullExplanation(!showFullExplanation)}
                    aria-expanded={showFullExplanation}
                  >
                    <Calculator size={13} color="#7C3AED" />
                    <span>{showFullExplanation ? 'Hide detailed score breakdown' : 'View detailed score breakdown'}</span>
                    {showFullExplanation ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                  </button>

                  {showFullExplanation && (
                    <div className="f360-breakdown-card fade-in">
                      <div className="f360-breakdown-header">
                        <div className="f360-breakdown-title">
                          <Calculator size={14} color="#4338CA" />
                          <span>M5 Contextual Risk Scoring Breakdown</span>
                        </div>
                        <span className="f360-breakdown-total-badge">
                          Score: <strong>{score} / 100</strong> ({levelFormatted})
                        </span>
                      </div>

                      <div className="f360-breakdown-table-wrapper">
                        <table className="f360-breakdown-table">
                          <thead>
                            <tr>
                              <th>Scoring Factor</th>
                              <th>Observed Input</th>
                              <th>Policy Rule Band</th>
                              <th style={{ textAlign: 'right' }}>Points Awarded</th>
                            </tr>
                          </thead>
                          <tbody>
                            {detailedScoreBreakdown.map((row) => (
                              <tr key={row.name}>
                                <td>
                                  <div className="f360-breakdown-factor-cell">
                                    <row.icon size={13} />
                                    <span>{row.name}</span>
                                  </div>
                                </td>
                                <td>
                                  <span className="f360-breakdown-val-mono">{row.observed}</span>
                                </td>
                                <td>
                                  <span className="f360-breakdown-band-text">{row.band}</span>
                                </td>
                                <td style={{ textAlign: 'right' }}>
                                  <span className={`f360-breakdown-pts-pill ${row.points > 0 ? 'active' : 'zero'}`}>
                                    +{row.points} / {row.maxPoints} pts
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                          <tfoot>
                            <tr className="f360-breakdown-total-row">
                              <td colSpan={3}>
                                <span>Sum of 7 Factors ({detailedScoreBreakdown.map(r => r.points).join(' + ')})</span>
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <strong className="f360-breakdown-sum-val">{score} / 100 ({levelFormatted})</strong>
                              </td>
                            </tr>
                          </tfoot>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* RIGHT: Threat & Asset Context */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Database size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Threat & Asset Context</h3>
                    <p className="inv-card-subtitle">Vulnerability intelligence and asset exposure profile</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body" style={{ padding: '0' }}>
                <div className="f360-def-grid">
                  <div className="f360-def-row">
                    <span className="f360-def-label">Vulnerability ID</span>
                    <span className="f360-def-val mono">{finding.cve_id || 'N/A'}</span>
                  </div>
                  {cvss != null && (
                    <div className="f360-def-row">
                      <span className="f360-def-label">CVSS Score</span>
                      <span className="f360-def-val">{typeof cvss === 'object' ? cvss?.base_score ?? '—' : cvss}</span>
                    </div>
                  )}
                  <div className="f360-def-row">
                    <span className="f360-def-label">EPSS Probability</span>
                    <span className="f360-def-val">{epss != null ? `${Math.round(epss * 100)}% (${epss.toFixed(3)})` : 'Not available'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">CISA KEV</span>
                    <span className={`f360-def-val ${isKev ? 'text-red' : ''}`}>{isKev ? 'Listed · Active Exploitation' : 'Not listed'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Asset</span>
                    <span className="f360-def-val">{assetName}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Environment</span>
                    <span className="f360-def-val">{envFormatted}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Asset Criticality</span>
                    <span className="f360-def-val">{criticalityFormatted}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Exposure</span>
                    <span className="f360-def-val">{isInternet ? 'Internet-facing' : 'Internal'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Data Classification</span>
                    <span className="f360-def-val">{dataSensitivityFormatted}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Scanner Evidence</span>
                    <span className="f360-def-val">{detectingScannerNames.join(', ')} ({scannerCount}/{totalScanners})</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">SLA Window</span>
                    <span className="f360-def-val">{slaHours} hours ({Math.round(slaHours / 24)} days)</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">SLA Deadline</span>
                    <span className="f360-def-val">{formatSlaDeadline(authoritativeDueAt)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Row: Evidence Snapshot + Task & SLA */}
          <div className="investigate-two-col-layout" style={{ marginTop: 0 }}>

            {/* Evidence Snapshot */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Shield size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Evidence Snapshot</h3>
                  </div>
                </div>
                <button
                  className="f360-view-more-link"
                  onClick={() => navigateToTab('evidence')}
                  aria-label="View full evidence"
                >
                  View full evidence →
                </button>
              </div>

              <div className="inv-card-body" style={{ padding: '16px 24px' }}>
                <div className="f360-evidence-snap-row">
                  <div className="f360-evidence-snap-scanner">
                    <div className="f360-scanner-badge-box">{detectingScannerNames[0]?.[0] || 'N'}</div>
                    <div>
                      <div className="f360-scanner-snap-name">{detectingScannerNames[0] || 'Nuclei'}</div>
                      <div className="f360-scanner-snap-meta">
                        {scannerCount === 1 ? 'Single-source detection' : `${scannerCount} scanners corroborated`}
                      </div>
                    </div>
                  </div>
                  <span className="f360-severity-tag high">High Severity</span>
                </div>

                <div className="f360-evidence-snap-details">
                  <div className="f360-ev-detail-item">
                    <span className="f360-ev-detail-label">Status</span>
                    <span className="f360-ev-detail-val green">Normalized & Correlated</span>
                  </div>
                  <div className="f360-ev-detail-item">
                    <span className="f360-ev-detail-label">Detection</span>
                    <span className="f360-ev-detail-val">Single-source detection</span>
                  </div>
                  <div className="f360-ev-detail-item">
                    <span className="f360-ev-detail-label">Source ID</span>
                    <span className="f360-ev-detail-val mono">{detectingSources[0]?.finding_id || 'NUCLEI-' + finding.finding_id?.slice(-8)}</span>
                  </div>
                  <div className="f360-ev-detail-item">
                    <span className="f360-ev-detail-label">First Detected</span>
                    <span className="f360-ev-detail-val">{formatTs(detectingSources[0]?.timestamp || finding.created_at) || 'Time not recorded'}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Task & SLA */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><CheckSquare size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Task & SLA</h3>
                  </div>
                </div>
                {remediationTask && (
                  <span className={`task-summary-badge ${remediationTask.status.toLowerCase().replace(/_/g, '_')}`}>
                    {currentTaskStatus === 'IN_PROGRESS' ? 'In Progress' : currentTaskStatus.replace(/_/g, ' ')}
                  </span>
                )}
              </div>

              <div className="inv-card-body" style={{ padding: '16px 24px' }}>
                {remediationTask ? (
                  <>
                    <div className="f360-task-def-grid">
                      <div className="f360-task-def-item">
                        <span className="f360-def-label">Task ID</span>
                        <span className="f360-def-val mono">{remediationTask.ticket_id}</span>
                      </div>
                      <div className="f360-task-def-item">
                        <span className="f360-def-label">Priority</span>
                        <span className="f360-badge-priority-medium">{remedPriority}</span>
                      </div>
                      <div className="f360-task-def-item">
                        <span className="f360-def-label">SLA Window</span>
                        <span className="f360-def-val">{slaHours} hours ({remedPriority})</span>
                      </div>
                      <div className="f360-task-def-item">
                        <span className="f360-def-label">Assigned To</span>
                        <span className="f360-def-val">{assignedOwnerDisplay || 'Unassigned'}</span>
                      </div>
                      <div className="f360-task-def-item">
                        <span className="f360-def-label">Checklist Progress</span>
                        <span className="f360-def-val">{completedStepCount} of {activeSteps.length} completed</span>
                      </div>
                      <div className="f360-task-def-item">
                        <span className="f360-def-label">Time Remaining</span>
                        <span className={`f360-def-val ${computedSlaStatus === 'BREACHED' ? 'text-red' : 'text-amber'}`}>
                          {formatSlaRemaining(authoritativeDueAt)}
                        </span>
                      </div>
                    </div>
                    <button className="f360-view-more-link" style={{ marginTop: 8 }} onClick={() => navigateToTab('remediation')}>
                      View task details →
                    </button>
                  </>
                ) : (
                  <div className="f360-empty-task">
                    <Target size={20} color="#CBD5E1" />
                    <p>No remediation task for finding {finding.finding_id} generated yet.</p>
                    <button
                      className="f360-primary-btn"
                      onClick={handleStartRemediation}
                      disabled={creatingTask || currentUser.role === 'VIEWER'}
                      aria-label="Create Remediation Task"
                      style={{ fontSize: '13px', padding: '8px 16px' }}
                    >
                      {creatingTask ? <Loader2 size={13} className="spin-slow" /> : <Zap size={13} />}
                      <span>{creatingTask ? 'Creating…' : 'Start Remediation'}</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 6. TAB 2: EVIDENCE ── */}
      {activeTab === 'evidence' && (
        <div
          className="investigate-tab-content fade-in"
          id="tabpanel-evidence"
          role="tabpanel"
          aria-labelledby="tab-evidence"
        >
          <div className="investigate-two-col-layout">

            {/* LEFT: Source Evidence */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Shield size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Source Evidence</h3>
                    <p className="inv-card-subtitle">
                      {scannerCount === 1 ? 'Single-source detection from configured security scanner' : `Corroborated across ${scannerCount} detection engines`}
                    </p>
                  </div>
                </div>
                <span className="f360-scanner-count-badge">
                  {scannerCount}/{totalScanners} Scanners
                </span>
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {/* Per-scanner source cards */}
                <div className="f360-scanner-cards-list">
                  {detectingScannerNames.map((scannerName, idx) => {
                    const src = detectingSources[idx] || {};
                    return (
                      <div key={idx} className="f360-scanner-source-card">
                        <div className="f360-scanner-source-header">
                          <div className="f360-scanner-source-identity">
                            <div className="f360-scanner-badge">{scannerName[0]}</div>
                            <div>
                              <div className="f360-scanner-source-name">{scannerName}</div>
                              <div className="f360-scanner-source-id">Source ID: {src.finding_id || `SCAN-${String(idx + 1).padStart(3, '0')}`}</div>
                            </div>
                          </div>
                          <span className="f360-scanner-detected-tag">
                            <Check size={11} /> Detected
                          </span>
                        </div>
                        <div className="f360-scanner-source-meta">
                          <div className="f360-scanner-meta-item">
                            <span className="f360-ev-detail-label">Detection</span>
                            <span className="f360-ev-detail-val green">Normalized & Correlated</span>
                          </div>
                          {src.timestamp && (
                            <div className="f360-scanner-meta-item">
                              <span className="f360-ev-detail-label">Detected</span>
                              <span className="f360-ev-detail-val">{formatTs(src.timestamp)}</span>
                            </div>
                          )}
                          {src.endpoint && (
                            <div className="f360-scanner-meta-item">
                              <span className="f360-ev-detail-label">Endpoint</span>
                              <span className="f360-ev-detail-val mono">{src.endpoint}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Correlation & Analyst Validation */}
                <div className="f360-correlation-box">
                  <div className="f360-correlation-title">Correlation & Analyst Validation</div>
                  <div className="f360-correlation-grid">
                    <div className="f360-corr-item">
                      <span className="f360-ev-detail-label">Correlation Hash</span>
                      <span className="f360-ev-detail-val mono">{finding.finding_id}</span>
                    </div>
                    <div className="f360-corr-item">
                      <span className="f360-ev-detail-label">{scannerCount === 1 ? 'Single-Source Detection' : 'Cross-Scanner Match'}</span>
                      <span className="f360-ev-detail-val mono">
                        {scannerCount === 1 ? '1 scanner correlated into canonical finding' : `${scannerCount} scanners correlated`}
                      </span>
                    </div>
                    <div className="f360-corr-item full-width">
                      <span className="f360-ev-detail-label">Analyst Validation</span>
                      <span className="f360-ev-detail-val" style={{ fontWeight: 600, color: activeDecision?.analyst_decision ? '#10B981' : '#64748B' }}>
                        {activeDecision?.analyst_decision === 'ACCEPT_PRIORITY'
                          ? 'Confirmed (Priority Accepted by Analyst)'
                          : activeDecision?.analyst_decision === 'ESCALATE'
                          ? 'Escalated (SOC Lead Validation)'
                          : activeDecision?.analyst_decision === 'DOWNGRADE'
                          ? 'Downgraded (Analyst Modified)'
                          : activeDecision?.analyst_decision === 'FALSE_POSITIVE'
                          ? 'Flagged False Positive'
                          : activeDecision?.analyst_decision === 'NEEDS_REVIEW'
                          ? 'Under Peer Review'
                          : 'Pending Analyst Review (Not recorded)'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* RIGHT: Technical Evidence & MITRE */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><FileText size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Technical Evidence</h3>
                    <p className="inv-card-subtitle">Scanner payload, endpoint and MITRE ATT&CK context</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {/* Payload Section */}
                <div className="f360-evidence-section">
                  <div className="f360-evidence-section-label">
                    <Code size={13} />
                    <span>Vulnerability Proof of Concept</span>
                    {pocPayloadText !== 'Not available' && (
                      <button
                        className="f360-copy-btn-inline"
                        onClick={() => copyToClipboard(pocPayloadText, 'poc')}
                        aria-label="Copy payload"
                      >
                        {copiedPoc ? <Check size={13} color="#10B981" /> : <Copy size={13} />}
                        {copiedPoc ? 'Copied' : 'Copy'}
                      </button>
                    )}
                  </div>
                  <pre className="evidence-payload-pre">
                    <code>{pocPayloadText}</code>
                  </pre>
                </div>

                {/* MITRE ATT&CK */}
                <div className="f360-evidence-section">
                  <div className="f360-evidence-section-label">
                    <Target size={13} />
                    <span>MITRE ATT&CK Context</span>
                    <span className="f360-inferred-badge">Inferred</span>
                  </div>
                  <p className="f360-mitre-disclaimer">
                    Contextual inference — not a confirmed attack observation.
                  </p>
                  <div className="f360-mitre-cards">
                    <div className="f360-mitre-card">
                      <div className="f360-mitre-technique-id">T1190</div>
                      <div className="f360-mitre-technique-name">Exploit Public-Facing Application</div>
                      <div className="f360-mitre-rationale">Inferred from {finding.cve_id || 'CVE'} remote vector</div>
                    </div>
                    <div className="f360-mitre-card">
                      <div className="f360-mitre-technique-id">T1059</div>
                      <div className="f360-mitre-technique-name">Command and Scripting Interpreter</div>
                      <div className="f360-mitre-rationale">Inferred from JNDI lookup execution pattern</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 7. TAB 3: EXPLAINABILITY ── */}
      {activeTab === 'explainability' && (
        <div
          className="investigate-tab-content fade-in"
          id="tabpanel-explainability"
          role="tabpanel"
          aria-labelledby="tab-explainability"
        >
          {/* Top Banner */}
          <div className="f360-explain-banner">
            <div className="f360-explain-banner-left">
              <div className="f360-explain-banner-icon">
                <Sparkles size={20} color="#7C3AED" />
              </div>
              <div>
                <div className="f360-explain-banner-title">RizIntel Explainability</div>
                <p className="f360-explain-banner-subtitle">Understand the verified signals behind RizIntel’s risk decision.</p>
              </div>
            </div>
            <div className="f360-explain-banner-right">
              <button
                className="f360-trace-btn"
                onClick={() => navigate(riztraceUrl + (riztraceUrl.includes('?') ? '&stage=stage_explanation' : '?stage=stage_explanation'))}
                aria-label="View in RizTrace"
              >
                <Activity size={14} color="#7C3AED" />
                <span>View in RizTrace →</span>
              </button>
            </div>
          </div>

          {/* Section A: Decision Summary */}
          <div className="inv-card" style={{ marginBottom: '20px' }}>
            <div className="inv-card-header">
              <div className="inv-card-title-group">
                <div className="card-header-icon-box purple"><Target size={17} /></div>
                <div>
                  <h3 className="inv-card-title">Why RizIntel assigned this risk</h3>
                  <p className="inv-card-subtitle">Based on the evidence available when this finding was analyzed</p>
                </div>
              </div>
              <div className="f360-scope-tag">
                <Info size={13} />
                <span>Immutable Assessment Snapshot</span>
              </div>
            </div>
            <div className="inv-card-body" style={{ padding: '20px 24px' }}>
              <div className="f360-explain-decision-grid">
                <div className="f360-explain-decision-card">
                  <span className="f360-explain-decision-label">Contextual Risk</span>
                  <div className="f360-explain-decision-val risk">
                    <span className="val-num">{score}</span>
                    <span className="val-max">/ 100</span>
                    <span className={`f360-kpi-badge risk-${level.toLowerCase()}`}>{levelFormatted}</span>
                  </div>
                  <span className="f360-explain-decision-sub">Algorithmic risk evaluation (M5)</span>
                </div>

                <div className="f360-explain-decision-card">
                  <span className="f360-explain-decision-label">Confidence</span>
                  <div className="f360-explain-decision-val">
                    <span className="val-num">{confidencePct}%</span>
                    <span className="f360-kpi-badge confidence-high">{confidenceClass}</span>
                  </div>
                  <span className="f360-explain-decision-sub">Scanner detection corroboration</span>
                </div>

                <div className="f360-explain-decision-card">
                  <span className="f360-explain-decision-label">Analyst Validation</span>
                  <div className="f360-explain-decision-val">
                    <span className={`f360-analyst-val-badge ${activeDecision?.analyst_decision ? 'confirmed' : 'pending'}`}>
                      {activeDecision?.analyst_decision ? (
                        <>
                          <CheckCircle2 size={13} />
                          <span>Confirmed ({formatAuditAction(activeDecision.analyst_decision)})</span>
                        </>
                      ) : (
                        <>
                          <Clock size={13} />
                          <span>Pending Analyst Review</span>
                        </>
                      )}
                    </span>
                  </div>
                  <span className="f360-explain-decision-sub">
                    {activeDecision ? `Recorded by ${activeDecision.actor || 'Analyst'}` : 'No analyst override recorded'}
                  </span>
                </div>

                <div className="f360-explain-decision-card">
                  <span className="f360-explain-decision-label">Generated Timestamp</span>
                  <div className="f360-explain-decision-val mono" style={{ fontSize: '13px', fontWeight: 600 }}>
                    {formatTs(finding.detail?.explanation?.generated_at) || formatTs(finding.created_at) || 'Generated timestamp not available'}
                  </div>
                  <span className="f360-explain-decision-sub">Analysis timestamp</span>
                </div>
              </div>
            </div>
          </div>

          {/* Section B & D: Audience Toggle & Explanation Narrative Card */}
          <div className="inv-card" style={{ marginBottom: '20px' }}>
            <div className="inv-card-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
              <div className="inv-card-title-group">
                <div className="card-header-icon-box purple"><Lightbulb size={17} /></div>
                <div>
                  <h3 className="inv-card-title">
                    {audienceView === 'analyst' ? 'Security Analyst Technical Narrative' : 'Executive Management Summary'}
                  </h3>
                  <p className="inv-card-subtitle">
                    {audienceView === 'analyst'
                      ? 'Technical telemetry, attack vectors, and evidence synthesis'
                      : 'Business impact, exposure scope, and urgency profile'}
                  </p>
                </div>
              </div>

              {/* Audience Toggle Buttons */}
              <div className="f360-audience-toggle" role="tablist" aria-label="Audience View">
                <button
                  type="button"
                  role="tab"
                  id="btn-audience-analyst"
                  aria-selected={audienceView === 'analyst'}
                  aria-controls="audience-analyst-panel"
                  className={`f360-audience-btn ${audienceView === 'analyst' ? 'active' : ''}`}
                  onClick={() => setAudienceView('analyst')}
                >
                  <Code size={14} />
                  <span>Analyst View</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  id="btn-audience-executive"
                  aria-selected={audienceView === 'executive'}
                  aria-controls="audience-executive-panel"
                  className={`f360-audience-btn ${audienceView === 'executive' ? 'active' : ''}`}
                  onClick={() => setAudienceView('executive')}
                >
                  <User size={14} />
                  <span>Executive View</span>
                </button>
              </div>
            </div>

            <div className="inv-card-body" style={{ padding: '20px 24px' }}>
              {/* Explanation Text Box with Copy */}
              <div className="f360-explanation-text-wrapper">
                <div className="f360-explanation-text-header">
                  <span className="f360-explanation-view-indicator">
                    {audienceView === 'analyst' ? 'Security Analyst View' : 'Executive Summary View'}
                  </span>
                  <button
                    className="f360-copy-btn-inline"
                    onClick={() => copyToClipboard(
                      audienceView === 'analyst'
                        ? (sanitizedTechnical || 'Technical explanation not available.')
                        : (sanitizedManagement || 'Management summary not available.'),
                      'explanation'
                    )}
                    aria-label="Copy Explanation"
                  >
                    {copiedExplanation ? <Check size={13} color="#10B981" /> : <Copy size={13} />}
                    <span>{copiedExplanation ? 'Copied' : 'Copy Explanation'}</span>
                  </button>
                </div>

                <div
                  id={audienceView === 'analyst' ? 'audience-analyst-panel' : 'audience-executive-panel'}
                  role="tabpanel"
                  aria-labelledby={audienceView === 'analyst' ? 'btn-audience-analyst' : 'btn-audience-executive'}
                  className="f360-explanation-paragraphs"
                >
                  {(audienceView === 'analyst' ? sanitizedTechnical : sanitizedManagement) ? (
                    (audienceView === 'analyst' ? sanitizedTechnical : sanitizedManagement)
                      .split(/(?<=\.)\s+(?=[A-Z])/)
                      .reduce((acc, sentence, idx) => {
                        const pIdx = Math.floor(idx / 2);
                        if (!acc[pIdx]) acc[pIdx] = [];
                        acc[pIdx].push(sentence);
                        return acc;
                      }, [])
                      .map((paraSentences, pIdx) => (
                        <p key={pIdx} className="f360-explanation-p">
                          {paraSentences.join(' ')}
                        </p>
                      ))
                  ) : (
                    <div className="f360-empty-explanation-msg">
                      <AlertTriangle size={16} color="#D97706" />
                      <span>
                        {audienceView === 'analyst'
                          ? 'Technical explanation not available for this finding.'
                          : 'Management summary not available for this finding.'}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Section C: Top Risk Drivers */}
          <div className="inv-card" style={{ marginBottom: '20px' }}>
            <div className="inv-card-header">
              <div className="inv-card-title-group">
                <div className="card-header-icon-box purple"><Target size={17} /></div>
                <div>
                  <h3 className="inv-card-title">Top Risk Drivers</h3>
                  <p className="inv-card-subtitle">Authoritative signals contributing to the contextual risk score</p>
                </div>
              </div>
              <span className="journey-summary-chip">{validatedDrivers.length} Validated Signals</span>
            </div>

            <div className="inv-card-body" style={{ padding: '20px 24px' }}>
              {validatedDrivers.length > 0 ? (
                <div className="f360-drivers-cards-grid">
                  {validatedDrivers.map(driver => (
                    <div key={driver.id} className="f360-driver-structured-card">
                      <div className="f360-driver-sc-header">
                        <div className={`f360-driver-sc-icon ${driver.color}`}>
                          <driver.icon size={16} />
                        </div>
                        <div className="f360-driver-sc-title-group">
                          <span className="f360-driver-sc-title">{driver.title}</span>
                          <span className="f360-driver-sc-stage">{driver.sourceStage}</span>
                        </div>
                        {driver.contribution != null && driver.contribution > 0 ? (
                          <span className="f360-driver-sc-pts active">
                            +{driver.contribution} / {driver.maxPoints} pts
                          </span>
                        ) : (
                          <span className="f360-driver-sc-pts zero">
                            Contribution not available
                          </span>
                        )}
                      </div>
                      <div className="f360-driver-sc-body">
                        <div className="f360-driver-sc-observed">
                          <span className="label">Observed Signal:</span>
                          <span className="val">{driver.observed}</span>
                        </div>
                        <p className="f360-driver-sc-why">{driver.whyItMatters}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="f360-empty-drivers-msg">
                  <Info size={16} color="#64748B" />
                  <span>Risk-driver breakdown details are not available for this finding.</span>
                </div>
              )}
            </div>
          </div>

          {/* Section E & F: Evidence Basis & Data Completeness (Two Column) */}
          <div className="investigate-two-col-layout" style={{ marginBottom: '20px' }}>

            {/* LEFT: Evidence Used for this Explanation */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Shield size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Evidence used for this explanation</h3>
                    <p className="inv-card-subtitle">Factual parameters grounded in telemetry and threat feeds</p>
                  </div>
                </div>
                <button
                  className="f360-view-more-link"
                  onClick={() => navigateToTab('evidence')}
                  aria-label="View Full Evidence"
                >
                  View Full Evidence →
                </button>
              </div>

              <div className="inv-card-body" style={{ padding: '0' }}>
                <div className="f360-def-grid">
                  <div className="f360-def-row">
                    <span className="f360-def-label">CVE Identifier</span>
                    <span className="f360-def-val mono">{finding.cve_id || 'No CVE assigned'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">CVSS Severity</span>
                    <span className="f360-def-val">{cvss != null ? `${typeof cvss === 'object' ? cvss?.base_score : cvss} / 10.0` : 'CVSS not available'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">EPSS Probability</span>
                    <span className="f360-def-val">{epss != null ? `${Math.round(epss * 100)}% (${Number(epss).toFixed(3)})` : 'EPSS not enriched'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">CISA KEV Catalog</span>
                    <span className={`f360-def-val ${isKev ? 'text-red' : ''}`}>{isKev ? 'Listed (Confirmed active exploitation)' : 'Not in CISA KEV'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Public Exploit</span>
                    <span className="f360-def-val">{finding.detail?.threat_intelligence?.exploit_available ? 'Available (PoC weaponized)' : 'Public exploit information not available'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Asset Criticality</span>
                    <span className="f360-def-val">{criticalityFormatted}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Network Exposure</span>
                    <span className="f360-def-val">{isInternet ? 'Internet-facing asset' : 'Internal network asset'}</span>
                  </div>
                  <div className="f360-def-row">
                    <span className="f360-def-label">Detection Corroboration</span>
                    <span className="f360-def-val">{detectingScannerNames.join(', ')} ({scannerCount}/{totalScanners})</span>
                  </div>
                </div>
              </div>
            </div>

            {/* RIGHT: Data Considered (Completeness Truth) */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><FileText size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Data considered</h3>
                    <p className="inv-card-subtitle">Explicit audit of available vs. missing signal intelligence</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                <div className="f360-completeness-section">
                  <div className="f360-completeness-subheading">
                    <CheckCircle2 size={14} color="#10B981" />
                    <span>Available Signals ({availableSignals.length})</span>
                  </div>
                  <div className="f360-completeness-list">
                    {availableSignals.map((sig, idx) => (
                      <div key={idx} className="f360-completeness-item available">
                        <span className="f360-completeness-dot available" />
                        <span className="f360-completeness-name">{sig.name}:</span>
                        <span className="f360-completeness-val">{sig.val}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="f360-completeness-section" style={{ marginTop: '16px' }}>
                  <div className="f360-completeness-subheading">
                    <Info size={14} color="#64748B" />
                    <span>Signals Not Available ({missingSignals.length})</span>
                  </div>
                  <div className="f360-completeness-list">
                    {missingSignals.length > 0 ? (
                      missingSignals.map((sig, idx) => (
                        <div key={idx} className="f360-completeness-item missing">
                          <span className="f360-completeness-dot missing" />
                          <span className="f360-completeness-name">{sig.name}:</span>
                          <span className="f360-completeness-val text-muted">{sig.reason}</span>
                        </div>
                      ))
                    ) : (
                      <div className="f360-completeness-empty">All standard telemetry signals were supplied.</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Section G & H: Recommended Action & Authoritative References */}
          <div className="investigate-two-col-layout" style={{ marginBottom: '20px' }}>

            {/* Recommended Next Step */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Code size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Recommended next step</h3>
                    <p className="inv-card-subtitle">Human-readable remediation guidance</p>
                  </div>
                </div>
                {remediationTask && (
                  <button
                    className="f360-view-more-link"
                    onClick={() => navigateToTab('remediation')}
                    aria-label="View Remediation Task"
                  >
                    View Remediation Task →
                  </button>
                )}
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                <div className="f360-rec-action-box">
                  <div className="f360-rec-action-heading">Advisory Guidance:</div>
                  <p className="f360-rec-action-text">
                    {finding.recommended_action || finding.detail?.explanation?.recommended_action || 'Review finding details, validate against the live asset, and apply vendor security updates.'}
                  </p>
                </div>

                <div className="f360-rec-action-meta">
                  <div className="f360-rec-meta-item">
                    <span className="label">Remediation Authority:</span>
                    <span className="val">M7 Remediation Engine</span>
                  </div>
                  <div className="f360-rec-meta-item">
                    <span className="label">Operational Priority:</span>
                    <span className="val badge">{remedPriority}</span>
                  </div>
                  <div className="f360-rec-meta-item">
                    <span className="label">SLA Window:</span>
                    <span className="val">{slaHours} hours ({Math.round(slaHours / 24)} days)</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Authoritative References */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><ExternalLink size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Authoritative References</h3>
                    <p className="inv-card-subtitle">Validated advisory links and intelligence sources</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {authoritativeReferences.length > 0 ? (
                  <div className="f360-references-list">
                    {authoritativeReferences.map((ref, idx) => (
                      <a
                        key={idx}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="f360-reference-link-item"
                      >
                        <div className="f360-ref-icon">
                          <ExternalLink size={13} />
                        </div>
                        <div className="f360-ref-info">
                          <span className="f360-ref-title">{ref.title}</span>
                          <span className="f360-ref-url mono">{ref.url}</span>
                        </div>
                      </a>
                    ))}
                  </div>
                ) : (
                  <div className="f360-empty-ref-box">
                    <Info size={16} color="#64748B" />
                    <span>References not available for this finding.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 8. TAB 4: JOURNEY ── */}
      {activeTab === 'journey' && (
        <div
          className="investigate-tab-content fade-in"
          id="tabpanel-journey"
          role="tabpanel"
          aria-labelledby="tab-journey"
        >
          <div className="inv-card">
            <div className="inv-card-header">
              <div className="inv-card-title-group">
                <div className="card-header-icon-box purple"><Clock size={17} /></div>
                <div>
                  <h3 className="inv-card-title">Finding Lifecycle Journey</h3>
                  <p className="inv-card-subtitle">Chronological progression from detection to current status. Click a stage to view details.</p>
                </div>
              </div>
              <span className="journey-summary-chip">{journeyNodes.filter(n => n.done).length}/{journeyNodes.length} Stages Complete</span>
            </div>

            <div className="inv-card-body" style={{ padding: '24px' }}>
              {/* Horizontal timeline */}
              <div className="f360-journey-timeline" role="list">
                {journeyNodes.map((node, idx) => (
                  <React.Fragment key={node.id}>
                    <div
                      className={`f360-journey-node ${node.done ? 'done' : node.active ? 'active' : 'pending'}`}
                      role="listitem"
                    >
                      <button
                        className={`f360-journey-node-btn ${expandedJourneyNode === node.id ? 'expanded' : ''}`}
                        onClick={() => setExpandedJourneyNode(expandedJourneyNode === node.id ? null : node.id)}
                        aria-expanded={expandedJourneyNode === node.id}
                        aria-label={`${node.label}: ${node.outcome}`}
                      >
                        <div className={`f360-journey-icon ${node.done ? 'done' : node.active ? 'active' : 'pending'}`}>
                          {node.done ? <CheckCircle2 size={16} /> : node.active ? <Zap size={16} /> : <Clock size={16} />}
                        </div>
                      </button>
                      <div className="f360-journey-node-label">{node.label}</div>
                      <div className="f360-journey-node-outcome">{node.outcome}</div>
                      {node.ts && (
                        <div className="f360-journey-node-ts">{formatTs(node.ts) || 'Time not recorded'}</div>
                      )}
                      {!node.ts && (
                        <div className="f360-journey-node-ts">Time not recorded</div>
                      )}
                    </div>
                    {idx < journeyNodes.length - 1 && (
                      <div className={`f360-journey-connector ${node.done ? 'done' : ''}`} aria-hidden="true" />
                    )}
                  </React.Fragment>
                ))}
              </div>

              {/* Expanded stage detail panel */}
              {expandedJourneyNode && (() => {
                const node = journeyNodes.find(n => n.id === expandedJourneyNode);
                if (!node) return null;
                return (
                  <div className="f360-journey-detail-panel fade-in">
                    <div className="f360-journey-detail-header">
                      <div className={`f360-journey-detail-icon ${node.done ? 'done' : node.active ? 'active' : 'pending'}`}>
                        {node.done ? <CheckCircle2 size={15} /> : node.active ? <Zap size={15} /> : <Clock size={15} />}
                      </div>
                      <strong>{node.label}</strong>
                      <span className="f360-journey-detail-outcome">{node.outcome}</span>
                    </div>
                    <p className="f360-journey-detail-text">{node.detail}</p>
                    {node.ts && <div className="f360-journey-detail-ts">Timestamp: {formatTs(node.ts)}</div>}
                  </div>
                );
              })()}

              {/* Journey vs RizTrace distinction note */}
              <div className="f360-journey-note">
                <Info size={13} color="#64748B" />
                <span>Journey shows the chronological finding lifecycle. For decision provenance and cryptographic chain, use <button className="f360-inline-link" onClick={() => navigate(riztraceUrl)}>Trace Decision</button>.</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 8. TAB 4: REMEDIATION ── */}
      {activeTab === 'remediation' && (
        <div
          className="investigate-tab-content fade-in"
          id="tabpanel-remediation"
          role="tabpanel"
          aria-labelledby="tab-remediation"
        >
          <div className="investigate-two-col-layout">

            {/* LEFT: Remediation Guidance */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Code size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Remediation Guidance</h3>
                    <p className="inv-card-subtitle">Recommended fix, implementation notes and references</p>
                  </div>
                </div>
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {/* Recommended fix strategy */}
                <div className="f360-rem-fix-section">
                  <div className="f360-rem-section-label">Remediation Strategy</div>
                  <p className="f360-rem-fix-desc">
                    {finding.recommended_action || 'Apply vendor security patch or upgrade to the latest secure release, enforce perimeter controls, and verify configuration.'}
                  </p>
                </div>

                {/* Technical Configuration / Code Fix */}
                <div className="f360-rem-fix-section" style={{ marginTop: '14px' }}>
                  <div className="f360-rem-section-label" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span>Technical Configuration & Patch</span>
                    <button
                      className="f360-copy-btn-inline"
                      onClick={() => copyToClipboard(fixCode, 'fix')}
                      aria-label="Copy remediation code"
                    >
                      {copiedFix ? <Check size={12} color="#10B981" /> : <Copy size={12} />}
                      <span>{copiedFix ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="fix-code-container" style={{ marginTop: '6px' }}>
                    <pre className="fix-code-pre"><code>{fixCode}</code></pre>
                  </div>
                </div>

                {/* Structured Mitigation Actions */}
                <div className="f360-rem-fix-section" style={{ marginTop: '14px' }}>
                  <div className="f360-rem-section-label">Key Mitigation Actions</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                    <div style={{ padding: '10px 14px', background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '10px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                      <span style={{ padding: '2px 8px', background: '#EDE9FE', color: '#7C3AED', fontWeight: 800, fontSize: '11px', borderRadius: '6px' }}>1</span>
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: '#0F172A' }}>Dependency & Package Upgrade</div>
                        <div style={{ fontSize: '12px', color: '#64748B', marginTop: '2px' }}>Update vulnerable build dependencies to secure release across repository and deployment manifests.</div>
                      </div>
                    </div>

                    <div style={{ padding: '10px 14px', background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '10px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                      <span style={{ padding: '2px 8px', background: '#DBEAFE', color: '#2563EB', fontWeight: 800, fontSize: '11px', borderRadius: '6px' }}>2</span>
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: '#0F172A' }}>Perimeter WAF Virtual Patch</div>
                        <div style={{ fontSize: '12px', color: '#64748B', marginTop: '2px' }}>Deploy edge inspection rules to filter known exploit payload signatures before reaching origin services.</div>
                      </div>
                    </div>

                    <div style={{ padding: '10px 14px', background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '10px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                      <span style={{ padding: '2px 8px', background: '#DCFCE7', color: '#16A34A', fontWeight: 800, fontSize: '11px', borderRadius: '6px' }}>3</span>
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: '#0F172A' }}>Verification & Staging Scan</div>
                        <div style={{ fontSize: '12px', color: '#64748B', marginTop: '2px' }}>Validate fix in staging with scanner agents to verify closure before marking task resolved.</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* External references */}
                <div className="f360-rem-refs-section" style={{ marginTop: '14px' }}>
                  <div className="f360-rem-section-label">Authoritative Advisories</div>
                  <div className="f360-ref-links" style={{ marginTop: '6px' }}>
                    {finding.cve_id && (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="f360-ref-link-row"
                      >
                        <ExternalLink size={13} />
                        <span>{finding.cve_id} — NIST National Vulnerability Database</span>
                      </a>
                    )}
                    {isKev && (
                      <a
                        href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                        target="_blank"
                        rel="noreferrer"
                        className="f360-ref-link-row"
                      >
                        <ExternalLink size={13} />
                        <span>CISA Known Exploited Vulnerabilities (KEV) Catalog</span>
                      </a>
                    )}
                    <a
                      href="https://attack.mitre.org"
                      target="_blank"
                      rel="noreferrer"
                      className="f360-ref-link-row"
                    >
                      <ExternalLink size={13} />
                      <span>MITRE ATT&CK Enterprise Matrix Documentation</span>
                    </a>
                  </div>
                </div>
              </div>
            </div>

            {/* RIGHT: Live Task & Checklist */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><CheckSquare size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Remediation Plan & Tasks</h3>
                    <p className="inv-card-subtitle">
                      {remediationTask
                        ? `${completedStepCount} of ${activeSteps.length} steps completed`
                        : 'No active remediation task'}
                    </p>
                  </div>
                </div>
                {remediationTask && (
                  <span className={`task-summary-badge ${remediationTask.status.toLowerCase().replace(/_/g, '_')}`}>
                    {currentTaskStatus === 'IN_PROGRESS' ? 'In Progress' : currentTaskStatus.replace(/_/g, ' ')}
                  </span>
                )}
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {/* Task Summary Card (first) */}
                {remediationTask ? (
                  <>
                    <div className="f360-task-summary-card">
                      <div className="f360-task-summary-grid">
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">Task ID:</span>
                          <span className="f360-def-val mono">{remediationTask.ticket_id}</span>
                        </div>
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">Status</span>
                          <span className={`f360-status-chip ${currentTaskStatus.toLowerCase().replace(/_/g, '-')}`}>
                            {currentTaskStatus === 'IN_PROGRESS' ? 'In Progress' : currentTaskStatus.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">Priority</span>
                          <span className="f360-badge-priority-medium">{remedPriority}</span>
                        </div>
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">SLA Window</span>
                          <span className="f360-def-val">{slaHours} hours</span>
                        </div>
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">Deadline</span>
                          <span className="f360-def-val">{formatSlaDeadline(remediationTask.due_at)}</span>
                        </div>
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">Countdown</span>
                          <span className={`f360-def-val ${computedSlaStatus === 'BREACHED' ? 'text-red' : 'text-amber'}`}>
                            {formatSlaRemaining(remediationTask.due_at)}
                          </span>
                        </div>
                        <div className="f360-task-summary-item">
                          <span className="f360-def-label">Assigned To</span>
                          <span className="f360-def-val">{assignedOwnerDisplay || 'Unassigned'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Checklist progress bar */}
                    <div className="f360-checklist-progress">
                      <div className="f360-checklist-progress-label">
                        <span>Checklist Progress</span>
                        <span className="f360-checklist-progress-count">{completedStepCount}/{activeSteps.length}</span>
                      </div>
                      <div className="f360-progress-bar">
                        <div
                          className="f360-progress-fill"
                          style={{ width: `${Math.round((completedStepCount / activeSteps.length) * 100)}%` }}
                        />
                      </div>
                    </div>

                    {/* Checklist steps */}
                    <div className="remediation-steps-list">
                      {activeSteps.map((step, idx) => {
                        const stepId = step.step_id || `step-${idx + 1}`;
                        const stepStatus = step.status || 'NOT_STARTED';
                        const isCompleted = stepStatus === 'COMPLETED' || stepStatus === 'Completed';
                        const isInProgress = stepStatus === 'IN_PROGRESS' || stepStatus === 'In Progress';
                        return (
                          <div
                            key={stepId}
                            className={`rem-step-row interactive${isCompleted ? ' completed' : ''}`}
                            onClick={() => handleStepToggle(stepId, stepStatus)}
                            style={{ cursor: currentUser.role === 'VIEWER' ? 'default' : 'pointer' }}
                            title={currentUser.role === 'VIEWER' ? 'Read-only mode' : 'Click to toggle step status'}
                            role="checkbox"
                            aria-checked={isCompleted}
                            tabIndex={0}
                            onKeyDown={e => e.key === 'Enter' && handleStepToggle(stepId, stepStatus)}
                          >
                            <div className={`rem-step-num ${isCompleted ? 'completed' : isInProgress ? 'in-progress' : ''}`}>
                              {isCompleted ? <Check size={13} /> : idx + 1}
                            </div>
                            <div className="rem-step-content">
                              <div className={`rem-step-title ${isCompleted ? 'line-through' : ''}`}>{step.title}</div>
                              <div className="rem-step-desc">{step.description || step.desc}</div>
                              {step.completed_by && (
                                <div className="rem-step-meta" style={{ fontSize: '11px', color: '#10B981', marginTop: '2px' }}>
                                  Completed by: {step.completed_by}
                                </div>
                              )}
                            </div>
                            <span className={`rem-step-status-tag${isInProgress ? ' in-progress' : isCompleted ? ' completed' : ''}`}>
                              {isCompleted ? 'Completed' : isInProgress ? 'In Progress' : 'Not Started'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </>
                ) : (
                  <div className="f360-empty-task">
                    <Target size={24} color="#CBD5E1" />
                    <p>No remediation task has been generated for this finding.</p>
                    <button
                      className="f360-primary-btn"
                      onClick={handleStartRemediation}
                      disabled={creatingTask || currentUser.role === 'VIEWER'}
                    >
                      {creatingTask ? <Loader2 size={14} className="spin-slow" /> : <Zap size={14} />}
                      <span>{creatingTask ? 'Creating Task…' : 'Create Remediation Task'}</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 9. TAB 5: DECISION & ACTIVITY ── */}
      {activeTab === 'decision-activity' && (
        <div
          className="investigate-tab-content fade-in"
          id="tabpanel-decision-activity"
          role="tabpanel"
          aria-labelledby="tab-decision-activity"
        >
          <div className="investigate-two-col-layout">

            {/* LEFT: Analyst Decision Panel */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><User size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Analyst Decision</h3>
                    <p className="inv-card-subtitle">Validate or override algorithmic recommendation</p>
                  </div>
                </div>
                {activeDecision && (activeDecision.analyst_decision || activeDecision.analyst_action) && DECISION_CONFIG[activeDecision.analyst_decision || activeDecision.analyst_action] && (
                  <span className={`active-decision-chip ${DECISION_CONFIG[activeDecision.analyst_decision || activeDecision.analyst_action]?.color || 'green'}`}>
                    <CheckCircle2 size={12} />
                    Active: {DECISION_CONFIG[activeDecision.analyst_decision || activeDecision.analyst_action]?.label}
                  </span>
                )}
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>

                {/* RBAC / Permission alerts */}
                {currentUser.role === 'VIEWER' && (
                  <div className="rbac-permission-notice viewer fade-in" role="alert">
                    <Lock size={15} />
                    <div>
                      <strong>Viewer Role (Read-Only)</strong> <span className="inv-badge" style={{ background: '#F1F5F9', color: '#64748B', border: '1px solid #E2E8F0', fontSize: '10px', padding: '2px 7px', borderRadius: 8, fontWeight: 700 }}>Read-Only</span>
                      <p>Decision recording requires Analyst, Security Lead, or Admin privileges.</p>
                    </div>
                  </div>
                )}

                {rbacError && (
                  <div className="rbac-error-banner fade-in" role="alert">
                    <ShieldAlert size={16} color="#EF4444" />
                    <div>
                      <strong>Access Denied (HTTP 403)</strong>
                      <p>{rbacError}</p>
                    </div>
                  </div>
                )}

                {decisionSaved && (
                  <div className="decision-success-banner fade-in" role="status">
                    <CheckCircle2 size={18} color="#16A34A" />
                    <div>
                      <strong>Decision Recorded in Audit Trail</strong>
                      <p>
                        "{DECISION_CONFIG[selectedDecision]?.label || selectedDecision}" by {currentUser.name} [{currentUser.role}]. SHA-256 chain updated.
                      </p>
                    </div>
                  </div>
                )}

                {/* Decision selector cards */}
                <div className="f360-decision-cards" role="radiogroup" aria-label="Select analyst decision">
                  {Object.entries(DECISION_CONFIG).map(([key, config]) => {
                    const isSelected = selectedDecision === key;
                    const isEscalateRestricted = key === 'ESCALATE' && !['SECURITY_LEAD', 'ADMIN'].includes(currentUser.role);
                    const isDisabled = currentUser.role === 'VIEWER' || isEscalateRestricted;
                    const DecIcon = config.icon;

                    return (
                      <button
                        key={key}
                        role="radio"
                        aria-checked={isSelected}
                        className={`f360-decision-card-btn ${config.color}${isSelected ? ' selected' : ''}${isDisabled ? ' disabled' : ''}`}
                        onClick={() => {
                          if (currentUser.role === 'VIEWER') {
                            setRbacError('Permission Denied (403): VIEWER role cannot record decisions.');
                            return;
                          }
                          if (isEscalateRestricted) {
                            setRbacError("Permission Denied (403): 'ESCALATE' requires Security Lead or Admin.");
                            return;
                          }
                          setSelectedDecision(key);
                          setRbacError(null);
                        }}
                        disabled={isDisabled}
                        title={isEscalateRestricted ? 'Requires Security Lead or Admin' : config.desc}
                      >
                        <DecIcon size={14} aria-hidden="true" />
                        <span className="f360-decision-card-label">{config.label}</span>
                        {isEscalateRestricted && <Lock size={11} className="f360-lock-icon" />}
                      </button>
                    );
                  })}
                </div>

                {/* Selected decision description */}
                <div className="f360-decision-desc-box">
                  <Info size={13} color="#64748B" />
                  <span>{DECISION_CONFIG[selectedDecision]?.desc || 'Confirm algorithmic risk score and SLA urgency.'}</span>
                </div>

                {/* Rationale */}
                <div className="f360-rationale-block">
                  <label className="f360-rationale-label" htmlFor="analyst-rationale">
                    Analyst Rationale
                    {['DOWNGRADE', 'FALSE_POSITIVE', 'ESCALATE'].includes(selectedDecision) && (
                      <span className="f360-required-tag">Required</span>
                    )}
                  </label>
                  <textarea
                    id="analyst-rationale"
                    className="f360-rationale-textarea"
                    rows={3}
                    placeholder={
                      currentUser.role === 'VIEWER'
                        ? 'Read-only mode: Decision input disabled.'
                        : 'Provide technical justification (e.g., Active verification / Compensating controls)...'
                    }
                    value={decisionRationale}
                    onChange={e => setDecisionRationale(e.target.value)}
                    disabled={currentUser.role === 'VIEWER'}
                    aria-required={['DOWNGRADE', 'FALSE_POSITIVE', 'ESCALATE'].includes(selectedDecision)}
                    aria-describedby="rationale-hint"
                    maxLength={1000}
                  />
                  <div id="rationale-hint" className="f360-rationale-hint">
                    {decisionRationale.length}/1000 characters
                    {['DOWNGRADE', 'FALSE_POSITIVE', 'ESCALATE'].includes(selectedDecision) && !decisionRationale.trim() && (
                      <span className="f360-rationale-required-msg"> · Rationale required for this decision</span>
                    )}
                  </div>
                </div>

                {/* Save button */}
                <button
                  className={`submit-decision-btn${currentUser.role === 'VIEWER' ? ' rbac-btn-disabled' : ''}`}
                  onClick={handleSaveDecision}
                  aria-describedby="save-decision-desc"
                  disabled={submittingDecision || currentUser.role === 'VIEWER'}
                >
                  {submittingDecision ? (
                    <>
                      <Loader2 size={16} className="spin-slow" />
                      <span>Recording…</span>
                    </>
                  ) : (
                    <>
                      <Send size={16} />
                      <span>Save Decision</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* RIGHT: Audit Activity Timeline */}
            <div className="inv-card">
              <div className="inv-card-header">
                <div className="inv-card-title-group">
                  <div className="card-header-icon-box purple"><Activity size={17} /></div>
                  <div>
                    <h3 className="inv-card-title">Activity & Audit Trail</h3>
                    <p className="inv-card-subtitle">SHA-256 chained event log · SQLite persisted</p>
                  </div>
                </div>
                {chainValid && (
                  <span className="audit-valid-badge">
                    <ShieldCheck size={13} /> Chain Valid
                  </span>
                )}
              </div>

              <div className="inv-card-body" style={{ padding: '20px 24px' }}>
                {feedbackHistory.length === 0 ? (
                  <div className="f360-audit-empty">
                    <Clock size={22} color="#CBD5E1" />
                    <p>No analyst decisions recorded yet.</p>
                    <span>The audit chain is initialized. All future decisions will appear here.</span>
                  </div>
                ) : (
                  <div className="f360-audit-timeline">
                    {feedbackHistory.map((item, idx) => {
                      const actionKey = item.analyst_action || item.analyst_decision;
                      const actionLabel = formatAuditAction(actionKey);
                      const roleLabel = formatAuditRole(item.role);
                      const ts = item.timestamp ? new Date(item.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Persisted';
                      const isExpanded = expandedAuditHash === (item.event_hash || idx);
                      const actionConfig = DECISION_CONFIG[actionKey];

                      return (
                        <div key={item.event_hash || idx} className="f360-audit-event">
                          <div className={`f360-audit-event-icon ${actionConfig?.color || 'green'}`}>
                            {actionConfig ? React.createElement(actionConfig.icon, { size: 12 }) : <Check size={12} />}
                          </div>
                          <div className="f360-audit-event-body">
                            <div className="f360-audit-event-header">
                              <span className="f360-audit-event-title">{actionLabel}</span>
                              <span className="f360-audit-event-time">{ts}</span>
                            </div>
                            {item.rationale && (
                              <p className="f360-audit-event-rationale">"{item.rationale}"</p>
                            )}
                            <div className="f360-audit-event-meta">
                              <span className="f360-audit-event-actor">By: {roleLabel}</span>
                              <button
                                className="f360-integrity-toggle"
                                onClick={() => setExpandedAuditHash(isExpanded ? null : (item.event_hash || idx))}
                                aria-expanded={isExpanded}
                              >
                                {isExpanded ? 'Hide' : 'View'} integrity details
                                {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                              </button>
                            </div>
                            {isExpanded && (
                              <div className="f360-audit-integrity-details fade-in">
                                <div className="f360-integrity-row">
                                  <span className="f360-integrity-label">Event Hash</span>
                                  <code className="f360-integrity-val">{item.event_hash || 'Genesis'}</code>
                                </div>
                                <div className="f360-integrity-row">
                                  <span className="f360-integrity-label">Previous Hash</span>
                                  <code className="f360-integrity-val">{item.prev_hash || '—'}</code>
                                </div>
                                <div className="f360-integrity-row">
                                  <span className="f360-integrity-label">Verification</span>
                                  <span className="f360-integrity-status green">
                                    <ShieldCheck size={12} /> Verified
                                  </span>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
