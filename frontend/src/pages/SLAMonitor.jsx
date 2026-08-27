import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Clock, AlertTriangle, AlertCircle, CheckCircle2, ShieldCheck,
  Zap, Shield, Code, Globe, Server, Database, ArrowUpRight,
  ArrowRight, Sparkles, TrendingUp, Flame, Activity, Target,
  Timer, BarChart2, Users, Layers, Eye, RefreshCw, Search,
  Filter, X, ChevronRight, CheckSquare, User, Lock, ExternalLink,
  Info, CornerDownRight, ArrowDown
} from 'lucide-react';
import { getSLAItems, getBreachWarnings, getRemediationTasks, getTeamDisplayName, TEAM_DISPLAY_MAP } from '../services/slaService';
import { getFindings, getScanRunFindings, getAssetDisplayName, getCurrentUser } from '../services/findingsService';

/* ── SLA Helpers ── */
function formatSlaCountdown(dueAtStr, status, resolvedAtStr) {
  if (status === 'RESOLVED' || status === 'MET') {
    return { text: 'SLA Met', type: 'resolved', rawStatus: 'RESOLVED' };
  }
  if (!dueAtStr) {
    return { text: 'Deadline not available', type: 'none', rawStatus: 'NO_DEADLINE' };
  }

  const dueTime = new Date(dueAtStr).getTime();
  const now = Date.now();
  if (isNaN(dueTime)) {
    return { text: 'Deadline not available', type: 'none', rawStatus: 'NO_DEADLINE' };
  }

  const diffMs = dueTime - now;
  if (diffMs <= 0) {
    const overdueMins = Math.floor(Math.abs(diffMs) / 60000);
    const overdueHours = Math.floor(overdueMins / 60);
    const overdueDays = Math.floor(overdueHours / 24);
    let txt = `Breached ${overdueMins}m ago`;
    if (overdueDays > 0) txt = `Breached ${overdueDays}d ${overdueHours % 24}h ago`;
    else if (overdueHours > 0) txt = `Breached ${overdueHours}h ${overdueMins % 60}m ago`;
    return { text: txt, type: 'breached', rawStatus: 'BREACHED' };
  }

  const diffHours = Math.floor(diffMs / 3600000);
  const diffMins = Math.floor((diffMs % 3600000) / 60000);
  const diffDays = Math.floor(diffHours / 24);

  let text = '';
  if (diffDays >= 2) {
    text = `${diffDays}d ${diffHours % 24}h left`;
  } else if (diffHours >= 1) {
    text = `${diffHours}h ${diffMins}m left`;
  } else {
    text = `${Math.max(1, diffMins)}m left`;
  }

  const isAtRisk = diffHours <= 4 || diffMs <= (168 * 3600000 * 0.25);
  return {
    text,
    type: isAtRisk ? 'at_risk' : 'on_track',
    rawStatus: isAtRisk ? 'AT_RISK' : 'ON_TRACK',
    diffMs
  };
}

function calculateTimeConsumedPct(startedAtStr, dueAtStr, status) {
  if (status === 'RESOLVED' || status === 'MET') return 100;
  if (!dueAtStr) return 0;
  const due = new Date(dueAtStr).getTime();
  const start = startedAtStr ? new Date(startedAtStr).getTime() : (due - (168 * 3600000));
  const now = Date.now();
  if (isNaN(due) || isNaN(start) || due <= start) return 50;
  const elapsed = Math.max(0, now - start);
  const total = due - start;
  return Math.min(100, Math.max(0, Math.round((elapsed / total) * 100)));
}

export default function SLAMonitor() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const scanRunId = searchParams.get('scan_run_id') || '';
  const orgId = searchParams.get('org_id') || 'ORG-RIZZOLVE-DEMO';

  const [currentUser, setCurrentUser] = useState(() => getCurrentUser() || {
    name: 'SA Analyst',
    email: 'analyst@rizintel.demo',
    role: 'ANALYST',
    organization_id: orgId
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const [rawFindings, setRawFindings] = useState([]);
  const [persistedTasks, setPersistedTasks] = useState([]);
  const [breachWarnings, setBreachWarnings] = useState({ hard_breaches: [], predictive_warnings: [] });

  // View state: 'overview' | 'queue' | 'kanban' | 'team'
  const [activeView, setActiveView] = useState(() => searchParams.get('view') || 'overview');

  useEffect(() => {
    const v = searchParams.get('view');
    if (v && ['overview', 'queue', 'kanban', 'team'].includes(v)) {
      setActiveView(v);
    }
  }, [searchParams]);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSlaStatus, setFilterSlaStatus] = useState('ALL');
  const [filterWorkflow, setFilterWorkflow] = useState('ALL');
  const [filterPriority, setFilterPriority] = useState('ALL');
  const [filterRisk, setFilterRisk] = useState('ALL');
  const [filterOwner, setFilterOwner] = useState('ALL');
  const [sortBy, setSortBy] = useState('URGENCY'); // 'URGENCY' | 'DEADLINE' | 'RISK' | 'PRIORITY' | 'NEWEST'

  // Sync view state to query param
  const handleViewChange = (view) => {
    setActiveView(view);
    const newParams = new URLSearchParams(searchParams);
    newParams.set('view', view);
    setSearchParams(newParams, { replace: true });
  };

  // Primary Data Fetcher
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [findingsRes, tasksRes, warningsRes] = await Promise.allSettled([
        scanRunId ? getScanRunFindings(orgId, scanRunId) : getFindings({ organization_id: orgId }),
        getRemediationTasks({ organization_id: orgId }),
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

      let loadedWarnings = { hard_breaches: [], predictive_warnings: [] };
      if (warningsRes.status === 'fulfilled' && warningsRes.value) {
        loadedWarnings = warningsRes.value;
      }

      setRawFindings(loadedFindings);
      setPersistedTasks(loadedTasks);
      setBreachWarnings(loadedWarnings);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Failed to load SLA Monitor data:', err);
      setError('RizIntel could not retrieve remediation commitments right now.');
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

  // Unified Task/Finding Compilation (Authoritative Tenant Join)
  const compiledTasks = useMemo(() => {
    const taskMap = new Map();
    persistedTasks.forEach(t => {
      if (!t || !t.finding_id) return;
      const cleanFindingId = String(t.finding_id).trim();
      const cleanOrgId = String(t.organization_id || orgId).trim();
      const compositeKey = `${cleanOrgId}::${cleanFindingId}`;

      const existing = taskMap.get(compositeKey);
      if (!existing) {
        taskMap.set(compositeKey, t);
        taskMap.set(cleanFindingId, t);
      } else {
        const isExistingActive = existing.status !== 'RESOLVED';
        const isNewActive = t.status !== 'RESOLVED';
        if (!isExistingActive && isNewActive) {
          taskMap.set(compositeKey, t);
          taskMap.set(cleanFindingId, t);
        } else if (new Date(t.updated_at || t.created_at || 0) >= new Date(existing.updated_at || existing.created_at || 0)) {
          taskMap.set(compositeKey, t);
          taskMap.set(cleanFindingId, t);
        }
      }
    });

    return rawFindings.map((f, idx) => {
      const cleanFindingId = String(f.finding_id || '').trim();
      const findingOrgId = String(f.organization_id || orgId).trim();
      const task = taskMap.get(`${findingOrgId}::${cleanFindingId}`) || taskMap.get(cleanFindingId);

      const ticketId = task?.ticket_id || f.workflow?.ticket_id || `TCK-${cleanFindingId.slice(-8)}`;
      const workflowStatus = (task?.status || f.workflow?.status || 'OPEN').toUpperCase();

      // Authoritative ownership resolution
      let assigneeId = '';
      let assigneeDisplayName = 'Unassigned';
      let assigneeType = null;
      let isUnassigned = true;

      if (task) {
        assigneeId = String(task.assigned_to || '').trim();
        assigneeType = task.assignee_type || (assigneeId ? 'TEAM' : null);
        if (assigneeId && assigneeId !== '—' && assigneeId.toLowerCase() !== 'unassigned') {
          isUnassigned = false;
          assigneeDisplayName = task.assignee_display_name || getTeamDisplayName(assigneeId) || assigneeId;
        } else {
          isUnassigned = true;
          assigneeDisplayName = 'Unassigned';
          assigneeId = '';
        }
      } else if (f.workflow?.assigned_to) {
        const wfAssigned = String(f.workflow.assigned_to).trim();
        if (wfAssigned && wfAssigned !== '—' && wfAssigned.toLowerCase() !== 'unassigned') {
          isUnassigned = false;
          assigneeId = wfAssigned;
          assigneeDisplayName = getTeamDisplayName(wfAssigned) || wfAssigned;
          assigneeType = 'TEAM';
        }
      }

      const dueAt = task?.due_at || f.workflow?.sla_due_at || f.workflow?.sla_deadline || null;
      const startedAt = task?.discovered_at || task?.created_at || f.created_at || f.discovered_at || null;
      const slaHours = task?.sla_hours || f.workflow?.sla_hours || (f.risk_score >= 90 ? 4 : f.risk_score >= 70 ? 24 : f.risk_score >= 40 ? 168 : 720);

      const priority = (task?.priority || (slaHours <= 4 ? 'CRITICAL' : slaHours <= 24 ? 'HIGH' : slaHours <= 168 ? 'MEDIUM' : 'LOW')).toUpperCase();
      const contextualRiskLevel = (f.risk_level || 'HIGH').toUpperCase();
      const contextualRiskScore = f.risk_score ?? 68;

      const countdown = formatSlaCountdown(dueAt, workflowStatus, task?.resolved_at);

      // Determine authoritative SLA status
      let slaStatus = 'ON_TRACK';
      if (workflowStatus === 'RESOLVED') {
        slaStatus = 'RESOLVED';
      } else if (countdown.rawStatus === 'BREACHED' || f.workflow?.sla_status === 'BREACHED' || f.workflow?.sla_status === 'SLA_BREACHED') {
        slaStatus = 'BREACHED';
      } else if (countdown.rawStatus === 'AT_RISK' || f.workflow?.sla_status === 'AT_RISK' || f.workflow?.sla_status === 'APPROACHING_BREACH') {
        slaStatus = 'AT_RISK';
      }

      // Checklist progress
      let checklist = [];
      try {
        checklist = typeof task?.checklist_json === 'string' ? JSON.parse(task.checklist_json) : (Array.isArray(task?.checklist_json) ? task.checklist_json : []);
      } catch {
        checklist = [];
      }
      const totalSteps = checklist.length || 4;
      const completedSteps = checklist.filter(s => s.status === 'COMPLETED' || s.status === 'Completed').length || (workflowStatus === 'RESOLVED' ? 4 : (workflowStatus === 'IN_PROGRESS' ? 1 : 0));

      const timeConsumedPct = calculateTimeConsumedPct(startedAt, dueAt, workflowStatus);

      return {
        key: cleanFindingId || `task-${idx}`,
        finding_id: cleanFindingId,
        task_id: ticketId,
        ticket_id: ticketId,
        organization_id: findingOrgId,
        scan_run_id: f.scan_run_id || scanRunId || null,
        vulnerability_name: f.vulnerability_name || 'Vulnerability Finding',
        cve_id: f.cve_id || null,
        asset_id: f.asset_id,
        asset_name: f.detail?.asset_context?.asset_name || getAssetDisplayName(f.asset_id) || f.asset_id || 'Target Asset',
        asset_environment: f.detail?.asset_context?.environment || 'Production',
        risk_score: contextualRiskScore,
        risk_level: contextualRiskLevel,
        remediation_priority: priority,
        sla_hours: slaHours,
        sla_due_at: dueAt,
        sla_started_at: startedAt,
        workflow_status: workflowStatus,
        sla_status: slaStatus,
        is_unassigned: isUnassigned,
        assignee_type: assigneeType,
        assignee_id: assigneeId,
        owner_handle: assigneeId,
        owner_display_name: assigneeDisplayName,
        countdown_text: countdown.text,
        countdown_type: countdown.type,
        time_consumed_pct: timeConsumedPct,
        checklist_completed: completedSteps,
        checklist_total: totalSteps,
        resolved_at: task?.resolved_at || null,
        has_persisted_task: !!task
      };
    });
  }, [rawFindings, persistedTasks, orgId, scanRunId]);

  // Aggregate Metrics
  const summaryCounts = useMemo(() => {
    let breached = 0;
    let atRisk = 0;
    let onTrack = 0;
    let resolved = 0;
    let unassigned = 0;
    let assigned = 0;

    compiledTasks.forEach(t => {
      const isResolved = t.workflow_status === 'RESOLVED' || t.sla_status === 'RESOLVED';
      if (isResolved) {
        resolved++;
      } else if (t.sla_status === 'BREACHED') {
        breached++;
      } else if (t.sla_status === 'AT_RISK') {
        atRisk++;
      } else {
        onTrack++;
      }

      if (!isResolved) {
        if (t.is_unassigned) {
          unassigned++;
        } else {
          assigned++;
        }
      }
    });

    const activeTotal = breached + atRisk + onTrack;
    const eligibleTotal = activeTotal + resolved;
    const compliancePct = eligibleTotal > 0 ? Math.round(((onTrack + resolved) / eligibleTotal) * 100) : 0;

    return {
      activeTotal,
      assigned,
      breached,
      atRisk,
      onTrack,
      resolved,
      unassigned,
      eligibleTotal,
      compliancePct
    };
  }, [compiledTasks]);

  // Contextual Risk Distribution Counts
  const riskDistribution = useMemo(() => {
    const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    compiledTasks.forEach(t => {
      const lvl = t.risk_level || 'HIGH';
      if (dist[lvl] !== undefined) dist[lvl]++;
      else dist['HIGH']++;
    });
    return dist;
  }, [compiledTasks]);

  // Next SLA Deadline (Earliest tracked SLA commitment / deadline)
  const nextDeadlineTask = useMemo(() => {
    const withDue = compiledTasks.filter(t => t.sla_due_at);
    if (withDue.length === 0) return null;
    return [...withDue].sort((a, b) => {
      // 1. Prefer assigned tasks with persisted commitments over unassigned
      if (!a.is_unassigned !== !b.is_unassigned) return !a.is_unassigned ? -1 : 1;
      if (a.has_persisted_task !== b.has_persisted_task) return a.has_persisted_task ? -1 : 1;
      // 2. Earliest deadline
      const timeDiff = new Date(a.sla_due_at).getTime() - new Date(b.sla_due_at).getTime();
      if (timeDiff !== 0) return timeDiff;
      // 3. Higher contextual risk score
      return (b.risk_score || 0) - (a.risk_score || 0);
    })[0];
  }, [compiledTasks]);

  // Filtered & Sorted Tasks for Queue & Kanban
  const filteredTasks = useMemo(() => {
    return compiledTasks.filter(t => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = t.vulnerability_name.toLowerCase().includes(q);
        const matchCve = t.cve_id ? t.cve_id.toLowerCase().includes(q) : false;
        const matchAsset = t.asset_name.toLowerCase().includes(q);
        const matchFindingId = t.finding_id.toLowerCase().includes(q);
        const matchTicketId = t.ticket_id.toLowerCase().includes(q);
        const matchOwner = t.owner_display_name.toLowerCase().includes(q) || t.owner_handle.toLowerCase().includes(q);
        if (!matchTitle && !matchCve && !matchAsset && !matchFindingId && !matchTicketId && !matchOwner) {
          return false;
        }
      }

      if (filterSlaStatus !== 'ALL' && t.sla_status !== filterSlaStatus) return false;
      if (filterWorkflow !== 'ALL' && t.workflow_status !== filterWorkflow) return false;
      if (filterPriority !== 'ALL' && t.remediation_priority !== filterPriority) return false;
      if (filterRisk !== 'ALL' && t.risk_level !== filterRisk) return false;
      if (filterOwner === 'UNASSIGNED') {
        if (!t.is_unassigned) return false;
      } else if (filterOwner !== 'ALL') {
        if (t.owner_handle !== filterOwner) return false;
      }

      return true;
    }).sort((a, b) => {
      if (sortBy === 'URGENCY') {
        const rank = { 'BREACHED': 1, 'AT_RISK': 2, 'ON_TRACK': 3, 'RESOLVED': 4 };
        const diffRank = (rank[a.sla_status] || 5) - (rank[b.sla_status] || 5);
        if (diffRank !== 0) return diffRank;
        return (new Date(a.sla_due_at || 0).getTime()) - (new Date(b.sla_due_at || 0).getTime());
      }
      if (sortBy === 'DEADLINE') {
        return (new Date(a.sla_due_at || 0).getTime()) - (new Date(b.sla_due_at || 0).getTime());
      }
      if (sortBy === 'RISK') {
        return b.risk_score - a.risk_score;
      }
      if (sortBy === 'PRIORITY') {
        const pRank = { 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4 };
        return (pRank[a.remediation_priority] || 5) - (pRank[b.remediation_priority] || 5);
      }
      if (sortBy === 'NEWEST') {
        return (new Date(b.sla_started_at || 0).getTime()) - (new Date(a.sla_started_at || 0).getTime());
      }
      return 0;
    });
  }, [compiledTasks, searchQuery, filterSlaStatus, filterWorkflow, filterPriority, filterRisk, filterOwner, sortBy]);

  // Team Workload Map
  const teamWorkloadList = useMemo(() => {
    const map = new Map();

    // Seed default known teams
    ['secops', 'appsec-team', 'payments-infra', 'cloud-eng'].forEach(handle => {
      map.set(handle, {
        handle,
        displayName: getTeamDisplayName(handle),
        tasks: [],
        breached: 0,
        atRisk: 0,
        onTrack: 0,
        resolved: 0
      });
    });

    const unassignedGroup = {
      handle: 'UNASSIGNED',
      displayName: 'Unassigned Queue',
      tasks: [],
      breached: 0,
      atRisk: 0,
      onTrack: 0,
      resolved: 0
    };

    compiledTasks.forEach(t => {
      if (t.is_unassigned) {
        unassignedGroup.tasks.push(t);
        if (t.sla_status === 'BREACHED') unassignedGroup.breached++;
        else if (t.sla_status === 'AT_RISK') unassignedGroup.atRisk++;
        else if (t.sla_status === 'ON_TRACK') unassignedGroup.onTrack++;
        else if (t.sla_status === 'RESOLVED') unassignedGroup.resolved++;
      } else {
        const h = t.owner_handle;
        if (!map.has(h)) {
          map.set(h, {
            handle: h,
            displayName: t.owner_display_name,
            tasks: [],
            breached: 0,
            atRisk: 0,
            onTrack: 0,
            resolved: 0
          });
        }
        const g = map.get(h);
        g.tasks.push(t);
        if (t.sla_status === 'BREACHED') g.breached++;
        else if (t.sla_status === 'AT_RISK') g.atRisk++;
        else if (t.sla_status === 'ON_TRACK') g.onTrack++;
        else if (t.sla_status === 'RESOLVED') g.resolved++;
      }
    });

    const teams = Array.from(map.values()).filter(g => g.tasks.length > 0 || g.handle === 'secops' || g.handle === 'appsec-team');
    return { teams, unassigned: unassignedGroup };
  }, [compiledTasks]);

  // Navigate to canonical Finding360
  const handleInspectFinding = (findingId) => {
    const params = new URLSearchParams();
    if (orgId) params.set('organization_id', orgId);
    if (scanRunId) params.set('scan_run_id', scanRunId);
    const queryString = params.toString();
    navigate(`/findings/${findingId}${queryString ? `?${queryString}` : ''}`);
  };

  const handleResetFilters = () => {
    setSearchQuery('');
    setFilterSlaStatus('ALL');
    setFilterWorkflow('ALL');
    setFilterPriority('ALL');
    setFilterRisk('ALL');
    setFilterOwner('ALL');
    setSortBy('URGENCY');
  };

  const hasActiveFilters = searchQuery || filterSlaStatus !== 'ALL' || filterWorkflow !== 'ALL' || filterPriority !== 'ALL' || filterRisk !== 'ALL' || filterOwner !== 'ALL';

  return (
    <div className="slav2-root fade-in">

      {/* ── 1. Page Header Shell ── */}
      <div className="sla-header-shell">
        <div className="sla-header-left">
          <div className="sla-scope-pill">
            <Timer size={13} className="text-purple" />
            <span>SLA Automation & Governance</span>
            <span className="sla-scope-divider">/</span>
            <span className="sla-scope-org">{orgId}</span>
          </div>
          <h1 className="sla-header-title">Remediation SLA Monitor</h1>
          <p className="sla-header-subtitle">
            Track remediation commitments, identify breach risk, and coordinate ownership.
          </p>
        </div>

        <div className="sla-header-actions">
          <div className="sla-refresh-indicator">
            <span>Updated {lastRefreshed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            <button
              className="sla-refresh-btn"
              onClick={loadData}
              disabled={loading}
              title="Refresh SLA Metrics"
              aria-label="Refresh SLA metrics"
            >
              <RefreshCw size={13} className={loading ? 'spin-slow' : ''} />
            </button>
          </div>

          {currentUser.role === 'VIEWER' && (
            <div className="sla-viewer-badge" title="Viewer role has read-only access">
              <Lock size={12} />
              <span>Viewer (Read-Only)</span>
            </div>
          )}
        </div>
      </div>

      {/* ── Error Banner ── */}
      {error && (
        <div className="sla-error-banner" role="alert">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={18} color="#DC2626" />
            <div>
              <strong>Unable to load SLA data</strong>
              <div>{error}</div>
            </div>
          </div>
          <button className="sla-retry-btn" onClick={loadData}>
            Retry
          </button>
        </div>
      )}

      {/* ── 2. Summary Metrics Strip ── */}
      <div className="sla-summary-strip">
        <div
          className={`sla-metric-card ${filterSlaStatus === 'ALL' && activeView === 'queue' ? 'active' : ''}`}
          onClick={() => { setFilterSlaStatus('ALL'); handleViewChange('queue'); }}
          role="button"
          tabIndex={0}
          aria-label="Filter All Active SLAs"
        >
          <div className="sla-metric-top">
            <span className="sla-metric-label">Active SLAs</span>
            <Activity size={15} color="#64748B" />
          </div>
          <div className="sla-metric-value">{loading ? '—' : summaryCounts.activeTotal}</div>
          <div className="sla-metric-sub">In remediation queue</div>
        </div>

        <div
          className={`sla-metric-card red ${filterSlaStatus === 'BREACHED' ? 'active' : ''}`}
          onClick={() => { setFilterSlaStatus('BREACHED'); handleViewChange('queue'); }}
          role="button"
          tabIndex={0}
          aria-label="Filter Breached SLAs"
        >
          <div className="sla-metric-top">
            <span className="sla-metric-label">Breached</span>
            <AlertTriangle size={15} color="#DC2626" />
          </div>
          <div className="sla-metric-value text-red">{loading ? '—' : summaryCounts.breached}</div>
          <div className="sla-metric-sub">{summaryCounts.breached > 0 ? 'Exceeded deadline' : 'Zero breaches'}</div>
        </div>

        <div
          className={`sla-metric-card amber ${filterSlaStatus === 'AT_RISK' ? 'active' : ''}`}
          onClick={() => { setFilterSlaStatus('AT_RISK'); handleViewChange('queue'); }}
          role="button"
          tabIndex={0}
          aria-label="Filter At Risk SLAs"
        >
          <div className="sla-metric-top">
            <span className="sla-metric-label">At Risk</span>
            <Flame size={15} color="#D97706" />
          </div>
          <div className="sla-metric-value text-amber">{loading ? '—' : summaryCounts.atRisk}</div>
          <div className="sla-metric-sub">≤ 25% window remaining</div>
        </div>

        <div
          className={`sla-metric-card green ${filterSlaStatus === 'ON_TRACK' ? 'active' : ''}`}
          onClick={() => { setFilterSlaStatus('ON_TRACK'); handleViewChange('queue'); }}
          role="button"
          tabIndex={0}
          aria-label="Filter On Track SLAs"
        >
          <div className="sla-metric-top">
            <span className="sla-metric-label">On Track</span>
            <ShieldCheck size={15} color="#16A34A" />
          </div>
          <div className="sla-metric-value text-green">{loading ? '—' : summaryCounts.onTrack}</div>
          <div className="sla-metric-sub">Healthy turnaround time</div>
        </div>

        <div
          className={`sla-metric-card blue ${filterSlaStatus === 'RESOLVED' ? 'active' : ''}`}
          onClick={() => { setFilterSlaStatus('RESOLVED'); handleViewChange('queue'); }}
          role="button"
          tabIndex={0}
          aria-label="Filter Resolved SLAs"
        >
          <div className="sla-metric-top">
            <span className="sla-metric-label">Resolved</span>
            <CheckCircle2 size={15} color="#2563EB" />
          </div>
          <div className="sla-metric-value text-blue">{loading ? '—' : summaryCounts.resolved}</div>
          <div className="sla-metric-sub">SLA Commitments met</div>
        </div>

        <div
          className={`sla-metric-card purple ${filterOwner === 'UNASSIGNED' ? 'active' : ''}`}
          onClick={() => { setFilterOwner('UNASSIGNED'); handleViewChange('queue'); }}
          role="button"
          tabIndex={0}
          aria-label="Filter Unassigned Tasks"
        >
          <div className="sla-metric-top">
            <span className="sla-metric-label">Unassigned</span>
            <User size={15} color="#7C3AED" />
          </div>
          <div className="sla-metric-value text-purple">{loading ? '—' : summaryCounts.unassigned}</div>
          <div className="sla-metric-sub">Requires triage owner</div>
        </div>
      </div>

      {/* ── 3. Navigation View Bar ── */}
      <div className="sla-nav-bar" role="tablist" aria-label="SLA Monitor Views">
        <button
          className={`sla-nav-tab ${activeView === 'overview' ? 'active' : ''}`}
          onClick={() => handleViewChange('overview')}
          role="tab"
          aria-selected={activeView === 'overview'}
        >
          <BarChart2 size={14} />
          <span>Analysis Overview</span>
        </button>

        <button
          className={`sla-nav-tab ${activeView === 'queue' ? 'active' : ''}`}
          onClick={() => handleViewChange('queue')}
          role="tab"
          aria-selected={activeView === 'queue'}
        >
          <Layers size={14} />
          <span>Active SLA Queue</span>
          <span className="sla-tab-count">{compiledTasks.length}</span>
        </button>

        <button
          className={`sla-nav-tab ${activeView === 'kanban' ? 'active' : ''}`}
          onClick={() => handleViewChange('kanban')}
          role="tab"
          aria-selected={activeView === 'kanban'}
        >
          <CheckSquare size={14} />
          <span>Kanban Board</span>
        </button>

        <button
          className={`sla-nav-tab ${activeView === 'team' ? 'active' : ''}`}
          onClick={() => handleViewChange('team')}
          role="tab"
          aria-selected={activeView === 'team'}
        >
          <Users size={14} />
          <span>Team View</span>
          <span className="sla-tab-count">{teamWorkloadList.teams.length}</span>
        </button>
      </div>

      {/* ══════════════════════════════════════════════════════
          VIEW 1: ANALYSIS OVERVIEW
          ══════════════════════════════════════════════════════ */}
      {activeView === 'overview' && (
        <div className="sla-view-content fade-in">

          {/* Top Row: Next SLA Deadline Card */}
          {nextDeadlineTask && (
            <div className="sla-deadline-spotlight-card">
              <div className="sla-spotlight-left">
                <div className="sla-spotlight-eyebrow">
                  <span className="sla-spotlight-dot" />
                  <Clock size={13} color="#7C3AED" />
                  <span>NEXT SLA DEADLINE</span>
                </div>
                <h3 className="sla-spotlight-title">{nextDeadlineTask.vulnerability_name}</h3>
                <div className="sla-spotlight-meta">
                  <span className="sla-spotlight-cve">{nextDeadlineTask.cve_id || 'No CVE assigned'}</span>
                  <span className="sla-spotlight-asset">{nextDeadlineTask.asset_name}</span>
                  <span className="sla-spotlight-owner">
                    Owner: <strong>{nextDeadlineTask.owner_display_name}</strong>
                  </span>
                </div>
              </div>

              <div className="sla-spotlight-right">
                <div className="sla-spotlight-time-box">
                  <span className="sla-spotlight-time-label">Time Remaining</span>
                  <span className={`sla-spotlight-time-val ${nextDeadlineTask.countdown_type === 'breached' ? 'text-red' : (nextDeadlineTask.countdown_type === 'at_risk' ? 'text-amber' : 'text-green')}`}>
                    {nextDeadlineTask.countdown_text}
                  </span>
                  <span className="sla-spotlight-priority-badge">
                    {nextDeadlineTask.remediation_priority} Priority · {nextDeadlineTask.sla_hours}h SLA
                  </span>
                </div>
                <button
                  className="sla-spotlight-action-btn"
                  onClick={() => handleInspectFinding(nextDeadlineTask.finding_id)}
                  aria-label={`Inspect finding ${nextDeadlineTask.vulnerability_name}`}
                >
                  <span>Inspect Finding</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          )}

          {/* 3 Core Analysis Panels */}
          <div className="sla-overview-grid">

            {/* PANEL A: SLA Compliance & Status */}
            <div className="sla-panel-card">
              <div className="sla-panel-header">
                <div className="sla-panel-title-group">
                  <div className="sla-panel-icon-box purple"><ShieldCheck size={16} /></div>
                  <div>
                    <h3 className="sla-panel-title">SLA Compliance & Status</h3>
                    <p className="sla-panel-subtitle">Authoritative turnaround distribution</p>
                  </div>
                </div>
              </div>

              <div className="sla-panel-body">
                {compiledTasks.length === 0 ? (
                  <div className="sla-panel-empty">No active remediation commitments.</div>
                ) : (
                  <>
                    <div className="sla-compliance-rate-box">
                      <div className="sla-compliance-rate-num">{summaryCounts.compliancePct}%</div>
                      <div>
                        <div className="sla-compliance-rate-label">Overall SLA Compliance</div>
                        <div className="sla-compliance-rate-desc">
                          {summaryCounts.onTrack + summaryCounts.resolved} of {summaryCounts.eligibleTotal} eligible tasks compliant
                        </div>
                      </div>
                    </div>

                    <div className="sla-distribution-list">
                      <div className="sla-dist-row">
                        <span className="sla-dist-label"><span className="sla-dot green" /> On Track</span>
                        <span className="sla-dist-count">{summaryCounts.onTrack}</span>
                      </div>
                      <div className="sla-dist-row">
                        <span className="sla-dist-label"><span className="sla-dot amber" /> At Risk</span>
                        <span className="sla-dist-count">{summaryCounts.atRisk}</span>
                      </div>
                      <div className="sla-dist-row">
                        <span className="sla-dist-label"><span className="sla-dot red" /> Breached</span>
                        <span className="sla-dist-count">{summaryCounts.breached}</span>
                      </div>
                      <div className="sla-dist-row">
                        <span className="sla-dist-label"><span className="sla-dot blue" /> Resolved (Met)</span>
                        <span className="sla-dist-count">{summaryCounts.resolved}</span>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* PANEL B: Contextual Risk Distribution */}
            <div className="sla-panel-card">
              <div className="sla-panel-header">
                <div className="sla-panel-title-group">
                  <div className="sla-panel-icon-box red"><Target size={16} /></div>
                  <div>
                    <h3 className="sla-panel-title">Contextual Risk Distribution</h3>
                    <p className="sla-panel-subtitle">Grouped by M5 authoritative risk tier</p>
                  </div>
                </div>
              </div>

              <div className="sla-panel-body">
                <div className="sla-distribution-list">
                  <div className="sla-dist-row">
                    <span className="sla-dist-label">
                      <span className="sla-tag critical">CRITICAL</span>
                      <span className="sla-dist-sub">Tier 1 Critical Assets</span>
                    </span>
                    <span className="sla-dist-count">{riskDistribution.CRITICAL}</span>
                  </div>
                  <div className="sla-dist-row">
                    <span className="sla-dist-label">
                      <span className="sla-tag high">HIGH</span>
                      <span className="sla-dist-sub">Significant Threat Impact</span>
                    </span>
                    <span className="sla-dist-count">{riskDistribution.HIGH}</span>
                  </div>
                  <div className="sla-dist-row">
                    <span className="sla-dist-label">
                      <span className="sla-tag medium">MEDIUM</span>
                      <span className="sla-dist-sub">Scheduled Sprint Resolution</span>
                    </span>
                    <span className="sla-dist-count">{riskDistribution.MEDIUM}</span>
                  </div>
                  <div className="sla-dist-row">
                    <span className="sla-dist-label">
                      <span className="sla-tag low">LOW</span>
                      <span className="sla-dist-sub">Routine Maintenance</span>
                    </span>
                    <span className="sla-dist-count">{riskDistribution.LOW}</span>
                  </div>
                </div>

                <div className="sla-panel-footnote">
                  <Info size={12} color="#64748B" />
                  <span>Contextual risk reflects the authoritative risk classification of associated findings.</span>
                </div>
              </div>
            </div>

            {/* PANEL C: SLA Intelligence */}
            <div className="sla-panel-card">
              <div className="sla-panel-header">
                <div className="sla-panel-title-group">
                  <div className="sla-panel-icon-box blue"><Zap size={16} /></div>
                  <div>
                    <h3 className="sla-panel-title">SLA Intelligence</h3>
                    <p className="sla-panel-subtitle">Operational commitments & triage workload</p>
                  </div>
                </div>
              </div>

              <div className="sla-panel-body">
                <div className="sla-intel-stat-grid">
                  <div className="sla-intel-item">
                    <span className="sla-intel-label">Unassigned Active</span>
                    <span className="sla-intel-value text-purple">{summaryCounts.unassigned}</span>
                    <span className="sla-intel-sub">Awaiting ownership</span>
                  </div>

                  <div className="sla-intel-item">
                    <span className="sla-intel-label">Hard Breaches</span>
                    <span className="sla-intel-value text-red">{breachWarnings.hard_breaches?.length || summaryCounts.breached}</span>
                    <span className="sla-intel-sub">Requires executive notice</span>
                  </div>

                  <div className="sla-intel-item">
                    <span className="sla-intel-label">Predictive Warnings</span>
                    <span className="sla-intel-value text-amber">{breachWarnings.predictive_warnings?.length || summaryCounts.atRisk}</span>
                    <span className="sla-intel-sub">Automated early alerts</span>
                  </div>

                  <div className="sla-intel-item">
                    <span className="sla-intel-label">Avg Time to Fix</span>
                    <span className="sla-intel-value" style={{ fontSize: 14 }}>
                      {summaryCounts.resolved > 0 ? 'Resolved data available' : 'No resolved-task data'}
                    </span>
                    <span className="sla-intel-sub">{summaryCounts.resolved} resolved tasks</span>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          VIEW 2: ACTIVE SLA QUEUE
          ══════════════════════════════════════════════════════ */}
      {activeView === 'queue' && (
        <div className="sla-view-content fade-in">

          {/* Search & Filter Toolbar */}
          <div className="sla-toolbar">
            <div className="sla-search-box">
              <Search size={14} color="#64748B" />
              <input
                type="text"
                placeholder="Search by vulnerability, CVE, asset, task ID, or owner…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search SLA tasks"
              />
              {searchQuery && (
                <button className="sla-search-clear" onClick={() => setSearchQuery('')} aria-label="Clear search">
                  <X size={13} />
                </button>
              )}
            </div>

            <div className="sla-filter-group">
              <select
                className="sla-filter-select"
                value={filterSlaStatus}
                onChange={(e) => setFilterSlaStatus(e.target.value)}
                aria-label="Filter by SLA status"
              >
                <option value="ALL">SLA: All Statuses</option>
                <option value="BREACHED">Breached</option>
                <option value="AT_RISK">At Risk</option>
                <option value="ON_TRACK">On Track</option>
                <option value="RESOLVED">Resolved</option>
              </select>

              <select
                className="sla-filter-select"
                value={filterWorkflow}
                onChange={(e) => setFilterWorkflow(e.target.value)}
                aria-label="Filter by workflow status"
              >
                <option value="ALL">Workflow: All</option>
                <option value="OPEN">Open</option>
                <option value="ASSIGNED">Assigned</option>
                <option value="IN_PROGRESS">In Progress</option>
                <option value="RESOLVED">Resolved</option>
              </select>

              <select
                className="sla-filter-select"
                value={filterPriority}
                onChange={(e) => setFilterPriority(e.target.value)}
                aria-label="Filter by remediation priority"
              >
                <option value="ALL">Priority: All</option>
                <option value="CRITICAL">Critical (4h)</option>
                <option value="HIGH">High (24h)</option>
                <option value="MEDIUM">Medium (168h)</option>
                <option value="LOW">Low (720h)</option>
              </select>

              <select
                className="sla-filter-select"
                value={filterRisk}
                onChange={(e) => setFilterRisk(e.target.value)}
                aria-label="Filter by contextual risk"
              >
                <option value="ALL">Risk: All</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                className="sla-filter-select"
                value={filterOwner}
                onChange={(e) => setFilterOwner(e.target.value)}
                aria-label="Filter by owner"
              >
                <option value="ALL">Owner: All Teams</option>
                <option value="secops">SOC Operations Team</option>
                <option value="appsec-team">Application Security</option>
                <option value="payments-infra">Payments Engineering</option>
                <option value="cloud-eng">Cloud Infrastructure</option>
                <option value="UNASSIGNED">Unassigned Only</option>
              </select>

              <select
                className="sla-filter-select sort"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                aria-label="Sort SLA queue"
              >
                <option value="URGENCY">Sort: SLA Urgency</option>
                <option value="DEADLINE">Sort: Deadline (Soonest)</option>
                <option value="RISK">Sort: Contextual Risk (Highest)</option>
                <option value="PRIORITY">Sort: Priority</option>
                <option value="NEWEST">Sort: Newest Task</option>
              </select>

              {hasActiveFilters && (
                <button className="sla-reset-filters-btn" onClick={handleResetFilters} title="Reset all active filters">
                  <X size={12} />
                  <span>Clear All</span>
                </button>
              )}
            </div>
          </div>

          {/* Queue Task Cards List */}
          {loading ? (
            <div className="sla-skeleton-list">
              {[1, 2, 3, 4].map(n => (
                <div key={n} className="sla-skeleton-card" />
              ))}
            </div>
          ) : filteredTasks.length === 0 ? (
            <div className="sla-empty-state-card">
              <div className="sla-empty-icon-box"><ShieldCheck size={28} color="#64748B" /></div>
              <h3 className="sla-empty-title">
                {hasActiveFilters ? 'No tasks match your filters' : 'No active remediation tasks'}
              </h3>
              <p className="sla-empty-desc">
                {hasActiveFilters
                  ? 'Try adjusting your search criteria, SLA status, or ownership filters.'
                  : 'Eligible findings will appear here after remediation begins.'}
              </p>
              {hasActiveFilters && (
                <button className="sla-empty-reset-btn" onClick={handleResetFilters}>
                  Reset Filters
                </button>
              )}
            </div>
          ) : (
            <div className="sla-task-cards-grid">
              {filteredTasks.map((t, idx) => (
                <div
                  key={t.key}
                  className={`sla-task-card ${t.sla_status === 'BREACHED' ? 'card-breached' : (t.sla_status === 'AT_RISK' ? 'card-at-risk' : '')}`}
                  onClick={() => handleInspectFinding(t.finding_id)}
                  role="button"
                  tabIndex={0}
                  aria-label={`Inspect finding ${t.vulnerability_name}`}
                >
                  {/* Top Line: Rank, Title, ID */}
                  <div className="sla-tc-header">
                    <div className="sla-tc-title-wrap">
                      <span className="sla-tc-rank">#{idx + 1}</span>
                      <div>
                        <h4 className="sla-tc-title">{t.vulnerability_name}</h4>
                        <div className="sla-tc-ids">
                          <span className="sla-tc-cve">{t.cve_id || 'No CVE assigned'}</span>
                          <span className="sla-tc-ticket-id">{t.ticket_id}</span>
                        </div>
                      </div>
                    </div>

                    <div className="sla-tc-countdown-box">
                      <span className={`sla-tc-countdown-badge ${t.countdown_type}`}>
                        <Clock size={11} />
                        <span>{t.countdown_text}</span>
                      </span>
                    </div>
                  </div>

                  {/* Meta Chips */}
                  <div className="sla-tc-meta-row">
                    <span className="sla-tc-meta-item">
                      <Server size={12} color="#64748B" />
                      <span>{t.asset_name}</span>
                    </span>

                    <span className="sla-tc-meta-item">
                      <User size={12} color="#64748B" />
                      <span className={t.is_unassigned ? 'text-purple font-bold' : ''}>
                        {t.owner_display_name}
                      </span>
                    </span>

                    <span className={`sla-pill-risk ${t.risk_level.toLowerCase()}`}>
                      Risk: {t.risk_level} · {t.risk_score}
                    </span>

                    <span className="sla-pill-priority">
                      Priority: {t.remediation_priority} ({t.sla_hours}h)
                    </span>

                    <span className={`sla-pill-workflow ${t.workflow_status.toLowerCase()}`}>
                      {t.workflow_status.replace('_', ' ')}
                    </span>
                  </div>

                  {/* Progress Bars Section */}
                  <div className="sla-tc-progress-section">
                    <div className="sla-tc-prog-row">
                      <div className="sla-tc-prog-label">
                        <span>SLA Time Consumed</span>
                        <span>{t.time_consumed_pct}%</span>
                      </div>
                      <div className="sla-tc-prog-track">
                        <div
                          className={`sla-tc-prog-fill ${t.sla_status === 'BREACHED' ? 'red' : (t.sla_status === 'AT_RISK' ? 'amber' : 'green')}`}
                          style={{ width: `${t.time_consumed_pct}%` }}
                        />
                      </div>
                    </div>

                    <div className="sla-tc-prog-row">
                      <div className="sla-tc-prog-label">
                        <span>Checklist Progress</span>
                        <span>{t.checklist_completed}/{t.checklist_total} steps</span>
                      </div>
                      <div className="sla-tc-prog-track">
                        <div
                          className="sla-tc-prog-fill purple"
                          style={{ width: `${Math.round((t.checklist_completed / t.checklist_total) * 100)}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Footer Action */}
                  <div className="sla-tc-footer">
                    <span className="sla-tc-finding-id">ID: {t.finding_id}</span>
                    <span className="sla-tc-inspect-link">
                      <span>Inspect Finding</span>
                      <ArrowRight size={12} />
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          VIEW 3: KANBAN BOARD
          ══════════════════════════════════════════════════════ */}
      {activeView === 'kanban' && (
        <div className="sla-view-content fade-in">
          <div className="sla-kanban-board">

            {/* COLUMN 1: OPEN */}
            <div className="sla-kanban-col">
              <div className="sla-kanban-col-header">
                <div className="sla-kanban-col-title">
                  <span className="sla-dot gray" />
                  <span>Open</span>
                </div>
                <span className="sla-kanban-count">
                  {compiledTasks.filter(t => t.workflow_status === 'OPEN').length}
                </span>
              </div>
              <div className="sla-kanban-col-body">
                {compiledTasks.filter(t => t.workflow_status === 'OPEN').map(t => (
                  <div key={t.key} className="sla-kanban-card" onClick={() => handleInspectFinding(t.finding_id)}>
                    <div className="sla-kc-top">
                      <span className="sla-kc-id">{t.ticket_id}</span>
                      <span className={`sla-tc-countdown-badge ${t.countdown_type}`}>{t.countdown_text}</span>
                    </div>
                    <div className="sla-kc-title">{t.vulnerability_name}</div>
                    <div className="sla-kc-asset">{t.asset_name}</div>
                    <div className="sla-kc-footer">
                      <span className="sla-pill-risk-sm">{t.risk_level}</span>
                      <span className="sla-kc-owner">{t.owner_display_name}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* COLUMN 2: ASSIGNED */}
            <div className="sla-kanban-col">
              <div className="sla-kanban-col-header">
                <div className="sla-kanban-col-title">
                  <span className="sla-dot purple" />
                  <span>Assigned</span>
                </div>
                <span className="sla-kanban-count">
                  {compiledTasks.filter(t => t.workflow_status === 'ASSIGNED').length}
                </span>
              </div>
              <div className="sla-kanban-col-body">
                {compiledTasks.filter(t => t.workflow_status === 'ASSIGNED').map(t => (
                  <div key={t.key} className="sla-kanban-card" onClick={() => handleInspectFinding(t.finding_id)}>
                    <div className="sla-kc-top">
                      <span className="sla-kc-id">{t.ticket_id}</span>
                      <span className={`sla-tc-countdown-badge ${t.countdown_type}`}>{t.countdown_text}</span>
                    </div>
                    <div className="sla-kc-title">{t.vulnerability_name}</div>
                    <div className="sla-kc-asset">{t.asset_name}</div>
                    <div className="sla-kc-footer">
                      <span className="sla-pill-risk-sm">{t.risk_level}</span>
                      <span className="sla-kc-owner font-bold">{t.owner_display_name}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* COLUMN 3: IN PROGRESS */}
            <div className="sla-kanban-col">
              <div className="sla-kanban-col-header">
                <div className="sla-kanban-col-title">
                  <span className="sla-dot amber" />
                  <span>In Progress</span>
                </div>
                <span className="sla-kanban-count">
                  {compiledTasks.filter(t => t.workflow_status === 'IN_PROGRESS').length}
                </span>
              </div>
              <div className="sla-kanban-col-body">
                {compiledTasks.filter(t => t.workflow_status === 'IN_PROGRESS').map(t => (
                  <div key={t.key} className="sla-kanban-card" onClick={() => handleInspectFinding(t.finding_id)}>
                    <div className="sla-kc-top">
                      <span className="sla-kc-id">{t.ticket_id}</span>
                      <span className={`sla-tc-countdown-badge ${t.countdown_type}`}>{t.countdown_text}</span>
                    </div>
                    <div className="sla-kc-title">{t.vulnerability_name}</div>
                    <div className="sla-kc-asset">{t.asset_name}</div>
                    <div className="sla-kc-prog-bar">
                      <div style={{ width: `${Math.round((t.checklist_completed / t.checklist_total) * 100)}%` }} />
                    </div>
                    <div className="sla-kc-footer">
                      <span className="sla-pill-risk-sm">{t.risk_level}</span>
                      <span className="sla-kc-owner">{t.owner_display_name}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* COLUMN 4: RESOLVED */}
            <div className="sla-kanban-col">
              <div className="sla-kanban-col-header">
                <div className="sla-kanban-col-title">
                  <span className="sla-dot blue" />
                  <span>Resolved</span>
                </div>
                <span className="sla-kanban-count">
                  {compiledTasks.filter(t => t.workflow_status === 'RESOLVED').length}
                </span>
              </div>
              <div className="sla-kanban-col-body">
                {compiledTasks.filter(t => t.workflow_status === 'RESOLVED').map(t => (
                  <div key={t.key} className="sla-kanban-card" onClick={() => handleInspectFinding(t.finding_id)}>
                    <div className="sla-kc-top">
                      <span className="sla-kc-id">{t.ticket_id}</span>
                      <span className="sla-tc-countdown-badge resolved">SLA Met</span>
                    </div>
                    <div className="sla-kc-title">{t.vulnerability_name}</div>
                    <div className="sla-kc-asset">{t.asset_name}</div>
                    <div className="sla-kc-footer">
                      <span className="sla-pill-risk-sm">{t.risk_level}</span>
                      <span className="sla-kc-owner">{t.owner_display_name}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          VIEW 4: TEAM VIEW
          ══════════════════════════════════════════════════════ */}
      {activeView === 'team' && (
        <div className="sla-view-content fade-in">
          <div className="sla-team-view-grid">

            {/* Unassigned Queue Card */}
            <div className="sla-team-card unassigned-card">
              <div className="sla-team-header">
                <div className="sla-team-title-wrap">
                  <div className="sla-team-avatar unassigned"><User size={16} /></div>
                  <div>
                    <h4 className="sla-team-name">Unassigned Tasks Queue</h4>
                    <span className="sla-team-sub">Requires triage owner</span>
                  </div>
                </div>
                <span className="sla-team-badge-unassigned">{teamWorkloadList.unassigned.tasks.length}</span>
              </div>

              <div className="sla-team-body">
                <div className="sla-team-stats-row">
                  <div><span>Breached:</span> <strong className="text-red">{teamWorkloadList.unassigned.breached}</strong></div>
                  <div><span>At Risk:</span> <strong className="text-amber">{teamWorkloadList.unassigned.atRisk}</strong></div>
                  <div><span>On Track:</span> <strong className="text-green">{teamWorkloadList.unassigned.onTrack}</strong></div>
                </div>

                <div className="sla-team-task-previews">
                  {teamWorkloadList.unassigned.tasks.slice(0, 3).map(t => (
                    <div key={t.key} className="sla-team-mini-task" onClick={() => handleInspectFinding(t.finding_id)}>
                      <span className="sla-tmt-name">{t.vulnerability_name}</span>
                      <span className="sla-tmt-time">{t.countdown_text}</span>
                    </div>
                  ))}
                </div>

                <button
                  className="sla-team-drill-btn"
                  onClick={() => { setFilterOwner('UNASSIGNED'); handleViewChange('queue'); }}
                >
                  View all unassigned ({teamWorkloadList.unassigned.tasks.length})
                </button>
              </div>
            </div>

            {/* Assigned Teams */}
            {teamWorkloadList.teams.map(team => (
              <div key={team.handle} className="sla-team-card">
                <div className="sla-team-header">
                  <div className="sla-team-title-wrap">
                    <div className="sla-team-avatar">
                      {team.displayName.charAt(0).toUpperCase()}
                    </div>
                    <div>
                      <h4 className="sla-team-name">{team.displayName}</h4>
                      <span className="sla-team-sub">Handle: {team.handle}</span>
                    </div>
                  </div>
                  <span className="sla-team-badge">{team.tasks.length} active</span>
                </div>

                <div className="sla-team-body">
                  <div className="sla-team-stats-row">
                    <div><span>Breached:</span> <strong className="text-red">{team.breached}</strong></div>
                    <div><span>At Risk:</span> <strong className="text-amber">{team.atRisk}</strong></div>
                    <div><span>On Track:</span> <strong className="text-green">{team.onTrack}</strong></div>
                    <div><span>Resolved:</span> <strong className="text-blue">{team.resolved}</strong></div>
                  </div>

                  <div className="sla-team-task-previews">
                    {team.tasks.slice(0, 3).map(t => (
                      <div key={t.key} className="sla-team-mini-task" onClick={() => handleInspectFinding(t.finding_id)}>
                        <span className="sla-tmt-name">{t.vulnerability_name}</span>
                        <span className="sla-tmt-time">{t.countdown_text}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    className="sla-team-drill-btn"
                    onClick={() => { setFilterOwner(team.handle); handleViewChange('queue'); }}
                  >
                    Filter queue for this team →
                  </button>
                </div>
              </div>
            ))}

          </div>
        </div>
      )}

    </div>
  );
}
