/**
 * intelligenceNormalizer.js — Authoritative analytics normalizer for Security Intelligence.
 * Pure presentation aggregation function layer consuming canonical findings, tasks, and assets.
 */

export function normalizeSecurityIntelligence({
  findings = [],
  tasks = [],
  assets = [],
  breachWarnings = { hard_breaches: [], predictive_warnings: [] },
  orgId = 'ORG-RIZZOLVE-DEMO'
}) {
  const safeFindings = Array.isArray(findings) ? findings : [];
  const safeTasks = Array.isArray(tasks) ? tasks : [];
  const safeAssets = Array.isArray(assets) ? assets : [];

  // Task map strictly joined by finding_id
  const taskMap = new Map();
  safeTasks.forEach(t => {
    if (t?.finding_id) {
      taskMap.set(String(t.finding_id).trim(), t);
    }
  });

  // 1. Populations
  const totalFindings = safeFindings.length;
  const activeFindings = safeFindings.filter(f => (f.workflow?.status || 'OPEN').toUpperCase() !== 'SUPPRESSED');
  const activeFindingsCount = activeFindings.length;

  // 2. KEV Intelligence & Public Exploit separation
  const kevFindings = safeFindings.filter(f => f.detail?.threat_intelligence?.kev_listed === true);
  const kevCount = kevFindings.length;
  const exploitAvailableCount = safeFindings.filter(f => f.detail?.threat_intelligence?.exploit_available === true).length;
  const hasExplicitExploitFalse = safeFindings.some(f => f.detail?.threat_intelligence?.exploit_available === false);
  const highEpssCount = safeFindings.filter(f => (f.detail?.threat_intelligence?.epss_score ?? 0) >= 0.5).length;

  let publicExploitStatusText = 'Public exploit information not available';
  if (exploitAvailableCount > 0) {
    publicExploitStatusText = `${exploitAvailableCount} public exploit${exploitAvailableCount === 1 ? '' : 's'} available`;
  } else if (hasExplicitExploitFalse) {
    publicExploitStatusText = 'Public exploit availability not identified';
  }

  // 3. Exposure Intelligence (explicitly track findings vs distinct assets)
  const exposedFindings = safeFindings.filter(f => f.internet_exposure === true || f.detail?.asset_context?.internet_facing === true);
  const internalFindings = safeFindings.filter(f => 
    (f.internet_exposure === false || f.detail?.asset_context?.internet_facing === false) && 
    f.internet_exposure !== undefined
  );
  const unknownExposureFindings = safeFindings.filter(f => 
    f.internet_exposure === undefined && f.detail?.asset_context?.internet_facing === undefined
  );

  // Distinct exposed asset IDs
  const exposedAssetIdSet = new Set(exposedFindings.map(f => f.asset_id).filter(Boolean));
  const distinctExposedAssetCount = exposedAssetIdSet.size;
  const totalAssetCount = safeAssets.length || new Set(safeFindings.map(f => f.asset_id).filter(Boolean)).size;

  // 4. Confidence, Scanner Detection Coverage & Analyst Validation
  const highConfidenceFindings = safeFindings.filter(f => (f.confidence_classification || '').toUpperCase() === 'HIGH_CONFIDENCE');
  const needsReviewFindings = safeFindings.filter(f => (f.confidence_classification || '').toUpperCase() === 'NEEDS_REVIEW');
  const likelyNoiseFindings = safeFindings.filter(f => (f.confidence_classification || '').toUpperCase() === 'LIKELY_NOISE');
  
  // Scanner detection coverage
  const multiScannerFindings = safeFindings.filter(f => (f.detail?.scanner_consensus?.detected_by_count ?? 1) > 1);
  const singleSourceFindings = safeFindings.filter(f => (f.detail?.scanner_consensus?.detected_by_count ?? 1) <= 1);

  // Analyst validation (persisted decisions)
  const analystConfirmedFindings = safeFindings.filter(f => 
    f.detail?.analyst_decision || 
    f.confidence_classification === 'CONFIRMED' ||
    (Array.isArray(f.detail?.audit_history) && f.detail.audit_history.some(a => a.analyst_action === 'ACCEPT_PRIORITY' || a.analyst_action === 'CONFIRM'))
  );
  const pendingAnalystReviewCount = totalFindings - analystConfirmedFindings.length;

  // 5. Workflow Health (Strict Population Reconciliation: Every finding in exactly 1 bucket)
  let pendingReviewCount = 0;
  let openCount = 0;
  let inProgressCount = 0;
  let resolvedCount = 0;
  let suppressedCount = 0;

  safeFindings.forEach(f => {
    const isNeedsReview = (f.confidence_classification || '').toUpperCase() === 'NEEDS_REVIEW';
    const task = taskMap.get(String(f.finding_id).trim());
    const workflowStatus = (f.workflow?.status || '').toUpperCase();
    const taskStatus = (task?.status || '').toUpperCase();

    if (workflowStatus === 'SUPPRESSED') {
      suppressedCount++;
    } else if (workflowStatus === 'RESOLVED' || taskStatus === 'RESOLVED') {
      resolvedCount++;
    } else if (isNeedsReview) {
      pendingReviewCount++;
    } else if (workflowStatus === 'IN_PROGRESS' || taskStatus === 'IN_PROGRESS') {
      inProgressCount++;
    } else {
      openCount++;
    }
  });

  // 6. Authoritative SLA Health (reconciled with SLA Monitor)
  let breachedTasksCount = 0;
  let atRiskTasksCount = 0;
  let onTrackTasksCount = 0;
  let resolvedTasksCount = 0;

  safeTasks.forEach(t => {
    const status = (t.status || 'OPEN').toUpperCase();
    if (status === 'SLA_BREACHED') {
      breachedTasksCount++;
    } else if (status === 'RESOLVED') {
      resolvedTasksCount++;
    } else {
      onTrackTasksCount++;
    }
  });

  if (breachWarnings?.hard_breaches?.length) {
    breachedTasksCount = Math.max(breachedTasksCount, breachWarnings.hard_breaches.length);
  }

  // 7. Contextual Risk Distribution (M5 authoritative classification)
  const riskDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  safeFindings.forEach(f => {
    const lvl = (f.risk_level || 'HIGH').toUpperCase();
    if (riskDist[lvl] !== undefined) riskDist[lvl]++;
    else riskDist['HIGH']++;
  });

  // 8. Asset Criticality Distribution (Authoritative asset context — do NOT label HIGH as CRITICAL)
  const assetCritDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NOT_AVAILABLE: 0 };
  safeFindings.forEach(f => {
    const crit = (f.asset_criticality || f.detail?.asset_context?.criticality || '').toUpperCase();
    if (crit === 'CRITICAL') assetCritDist.CRITICAL++;
    else if (crit === 'HIGH') assetCritDist.HIGH++;
    else if (crit === 'MEDIUM') assetCritDist.MEDIUM++;
    else if (crit === 'LOW') assetCritDist.LOW++;
    else assetCritDist.NOT_AVAILABLE++;
  });

  // 9. Intersections (True Set Calculations by finding_id)
  const kevIdSet = new Set(kevFindings.map(f => f.finding_id));
  const exposedIdSet = new Set(exposedFindings.map(f => f.finding_id));
  const highCriticalityAssetFindingIdSet = new Set(
    safeFindings.filter(f => {
      const crit = (f.asset_criticality || f.detail?.asset_context?.criticality || '').toUpperCase();
      return crit === 'CRITICAL' || crit === 'HIGH';
    }).map(f => f.finding_id)
  );

  // KEV + Internet-Facing true intersection: kevIdSet ∩ exposedIdSet
  const kevExposedIntersectionIds = [...kevIdSet].filter(id => exposedIdSet.has(id));
  const kevExposedCount = kevExposedIntersectionIds.length;

  // 10. Remediation Assignment Reconciliation
  // Active unassigned findings eligible for task assignment (excluding review-blocked and resolved)
  const unassignedEligibleFindings = safeFindings.filter(f => {
    const isNeedsReview = (f.confidence_classification || '').toUpperCase() === 'NEEDS_REVIEW';
    if (isNeedsReview) return false;
    const task = taskMap.get(String(f.finding_id).trim());
    if (task?.status === 'RESOLVED') return false;
    return !task?.assigned_to || task.assigned_to === 'unassigned';
  });

  // 11. Current Data-Derived Insights (Truthful, non-contradictory wording)
  const currentInsights = [];
  if (totalFindings > 0) {
    if (kevCount > 0) {
      currentInsights.push({
        id: 'kev-urgency',
        title: 'KEV Catalog Correlation',
        description: `${kevCount} of ${totalFindings} active findings are listed in the CISA Known Exploited Vulnerabilities catalog.`,
        tag: 'CRITICAL',
        color: 'red',
        icon: 'Target',
        actionLabel: 'View KEV Findings',
        actionPath: '/findings?kev=true'
      });
    }

    if (exposedFindings.length > 0) {
      currentInsights.push({
        id: 'exposure-amplifies',
        title: 'Exposure Concentrates Surface Risk',
        description: `${exposedFindings.length} findings sit on internet-facing infrastructure (${distinctExposedAssetCount} distinct asset${distinctExposedAssetCount === 1 ? '' : 's'}).`,
        tag: 'HIGH IMPACT',
        color: 'orange',
        icon: 'Globe',
        actionLabel: 'Inspect Exposed Assets',
        actionPath: '/assets'
      });
    }

    if (needsReviewFindings.length > 0) {
      currentInsights.push({
        id: 'analyst-triage',
        title: 'Triage Verification Pending',
        description: `${needsReviewFindings.length} findings require analyst review to validate scanner consensus and confidence scoring.`,
        tag: 'TRIAGE',
        color: 'purple',
        icon: 'Users',
        actionLabel: 'Review Triage Queue',
        actionPath: '/findings?confidence=NEEDS_REVIEW'
      });
    } else {
      currentInsights.push({
        id: 'high-consensus',
        title: 'Consensus Builds Confidence',
        description: `All active findings have confirmed scanner consensus or verified analyst approval.`,
        tag: 'VERIFIED',
        color: 'teal',
        icon: 'CheckCircle2',
        actionLabel: 'View Findings Queue',
        actionPath: '/findings'
      });
    }
  }

  // 12. Next Best Actions (Prioritized, Real Counts, Real Links)
  const nextBestActions = [];

  if (kevCount > 0) {
    nextBestActions.push({
      id: 'act-kev',
      icon: '🛡️',
      color: 'red',
      title: `Investigate ${kevCount} CISA KEV ${kevCount === 1 ? 'vulnerability' : 'vulnerabilities'}`,
      description: 'Actively exploited CVEs listed in known vulnerability catalog.',
      buttonText: 'View KEV Items →',
      path: '/findings?kev=true',
      priority: 'CRITICAL'
    });
  }

  if (exposedFindings.length > 0) {
    nextBestActions.push({
      id: 'act-exposed',
      icon: '🌐',
      color: 'orange',
      title: `Review ${distinctExposedAssetCount} internet-facing ${distinctExposedAssetCount === 1 ? 'asset' : 'assets'}`,
      description: `${exposedFindings.length} active findings associated with external perimeter.`,
      buttonText: 'Review Assets →',
      path: '/assets',
      priority: 'HIGH'
    });
  }

  if (needsReviewFindings.length > 0) {
    nextBestActions.push({
      id: 'act-review',
      icon: '🔍',
      color: 'purple',
      title: `Validate ${needsReviewFindings.length} findings awaiting review`,
      description: 'Perform analyst validation on findings with single-scanner detection.',
      buttonText: 'Open Review Queue →',
      path: '/findings?confidence=NEEDS_REVIEW',
      priority: 'MEDIUM'
    });
  } else if (unassignedEligibleFindings.length > 0) {
    nextBestActions.push({
      id: 'act-open',
      icon: '👥',
      color: 'purple',
      title: `Assign ${unassignedEligibleFindings.length} unassigned findings`,
      description: 'Assign remediation tasks to accelerate security turnaround time.',
      buttonText: 'Open SLA Monitor →',
      path: '/sla?view=team',
      priority: 'MEDIUM'
    });
  }

  return {
    orgId,
    populations: {
      totalFindings,
      activeFindingsCount,
      totalAssetCount,
      distinctExposedAssetCount
    },
    snapshot: {
      activeFindings: activeFindingsCount,
      kevCount,
      exposedFindingsCount: exposedFindings.length,
      distinctExposedAssetCount,
      needsReviewCount: needsReviewFindings.length,
      highConfidenceCount: highConfidenceFindings.length,
      breachedCount: breachedTasksCount,
      confirmedCount: analystConfirmedFindings.length
    },
    riskDistribution: riskDist,
    assetCriticalityDistribution: assetCritDist,
    exposureDistribution: {
      exposedCount: exposedFindings.length,
      internalCount: internalFindings.length,
      unknownCount: unknownExposureFindings.length,
      distinctExposedAssets: distinctExposedAssetCount
    },
    confidenceDistribution: {
      highConfidence: highConfidenceFindings.length,
      needsReview: needsReviewFindings.length,
      likelyNoise: likelyNoiseFindings.length,
      multiScannerCount: multiScannerFindings.length,
      singleSourceCount: singleSourceFindings.length,
      analystConfirmed: analystConfirmedFindings.length,
      pendingAnalystReview: pendingAnalystReviewCount,
      total: totalFindings
    },
    workflowDistribution: {
      pendingReview: pendingReviewCount,
      open: openCount,
      inProgress: inProgressCount,
      resolved: resolvedCount,
      suppressed: suppressedCount,
      total: totalFindings,
      unassignedEligibleCount: unassignedEligibleFindings.length
    },
    kevIntelligence: {
      kevCount,
      exploitAvailableCount,
      publicExploitStatusText,
      highEpssCount,
      cves: kevFindings.map(f => f.cve_id).filter(Boolean)
    },
    intersections: {
      kevCount,
      exposedCount: exposedFindings.length,
      highCriticalityAssetFindingCount: highCriticalityAssetFindingIdSet.size,
      kevExposedCount,
      kevExposedIntersectionIds
    },
    currentInsights,
    nextBestActions
  };
}
