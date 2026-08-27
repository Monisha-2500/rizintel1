/**
 * customerFacingText.js — Enterprise customer-facing text sanitation & formatting
 *
 * Removes internal engine names (M1-M8), raw Python enum strings,
 * unformatted boolean flags, and provides consistent SOC queue formatting.
 */

/**
 * Sanitizes machine-generated explanations for customer presentation.
 */
export function cleanCustomerText(text, finding = null) {
  if (!text || typeof text !== 'string') return '';

  let cleaned = text;

  // Replace M5/engine references
  cleaned = cleaned.replace(/scored\s+(\d+(?:\.\d+)?)\/100\s*\(([A-Z]+)\)\s*by\s+the\s+risk\s+engine\s*\(M5\)/gi, 'Risk score: $1/100 · $2');
  cleaned = cleaned.replace(/by\s+the\s+risk\s+engine\s*\(M5\)/gi, 'by the risk assessment engine');
  cleaned = cleaned.replace(/the\s+risk\s+engine\s*\(M5\)/gi, 'the risk assessment engine');
  cleaned = cleaned.replace(/\(M[1-8]\)/gi, '');
  cleaned = cleaned.replace(/\bM[1-8]-v[\d.]+\b/gi, 'v1.0');

  // Replace Python Enum representations
  cleaned = cleaned.replace(/CONFIDENCECLASSIFICATION\.HIGH_CONFIDENCE/gi, 'High Confidence');
  cleaned = cleaned.replace(/CONFIDENCECLASSIFICATION\.NEEDS_REVIEW/gi, 'Needs Review');
  cleaned = cleaned.replace(/CONFIDENCECLASSIFICATION\.CONFIRMED/gi, 'Confirmed');
  cleaned = cleaned.replace(/CONFIDENCECLASSIFICATION\.LIKELY_NOISE/gi, 'Likely Noise');
  cleaned = cleaned.replace(/CONFIDENCECLASSIFICATION\.LOW_CONFIDENCE/gi, 'Low Confidence');

  // Replace raw booleans in explanations
  cleaned = cleaned.replace(/CISA\s+KEV\s+listed\s*=\s*True/gi, 'Listed in CISA KEV');
  cleaned = cleaned.replace(/CISA\s+KEV\s+listed\s*=\s*False/gi, 'Not listed in CISA KEV');
  cleaned = cleaned.replace(/exploit\s+available\s*=\s*True/gi, 'Public exploit available');
  cleaned = cleaned.replace(/exploit\s+available\s*=\s*False/gi, 'No public exploit available');
  cleaned = cleaned.replace(/internet-facing\s*=\s*True/gi, 'Internet-facing');
  cleaned = cleaned.replace(/internet-facing\s*=\s*False/gi, 'Internal network');

  // Replace informal CVE strings
  cleaned = cleaned.replace(/\(an unidentified CVE\)/gi, '(unassigned CVE)');
  cleaned = cleaned.replace(/NO-CVE-ASSIGNED/gi, 'No CVE assigned');

  // Remove fallback UNKNOWN data-sensitivity sentences
  cleaned = cleaned.replace(/\s*This system handles UNKNOWN-classified data\.?/gi, '');
  cleaned = cleaned.replace(/\s*This system handles UNKNOWN data\.?/gi, '');

  // Harmonize asset context with finding record if provided
  const resolvedAssetName = finding?.detail?.asset_context?.asset_name || finding?.asset_name;
  const isResolved = resolvedAssetName &&
    resolvedAssetName !== 'Unresolved Asset' &&
    resolvedAssetName !== 'Unmapped Asset' &&
    !resolvedAssetName.startsWith('host-');

  const rawCrit = finding?.asset_criticality || finding?.detail?.asset_context?.criticality;
  const hasKnownCrit = rawCrit && rawCrit.toUpperCase() !== 'UNKNOWN';

  if (isResolved) {
    cleaned = cleaned.replace(/\bUnresolved Asset\b/g, resolvedAssetName);
    cleaned = cleaned.replace(/\bon asset UNMAPPED\b/gi, `on ${resolvedAssetName}`);
  }

  if (hasKnownCrit) {
    cleaned = cleaned.replace(/which is a\s+unknown asset/gi, `which is a ${rawCrit.toLowerCase()} asset`);
    cleaned = cleaned.replace(/which is an?\s+unclassified asset(?:\s+in the registry)?/gi, `which is a ${rawCrit.toLowerCase()} asset`);
  } else {
    cleaned = cleaned.replace(/which is a\s+unknown asset/gi, 'which is currently unclassified in the asset registry');
  }

  // Clean double spaces or dangling punctuation
  cleaned = cleaned.replace(/\s{2,}/g, ' ').trim();

  return cleaned;
}

/**
 * Returns a concise 1-2 line summary for the finding queue card.
 */
export function getWhyItMatters(finding) {
  if (!finding) return 'Prioritized security threat requiring remediation.';

  // Check management or technical explanation
  const rawMgmt = finding.detail?.explanation?.management;
  const rawTech = finding.detail?.explanation?.technical;

  if (rawMgmt) {
    const clean = cleanCustomerText(rawMgmt, finding);
    // Grab first 1-2 sentences
    const sentences = clean.split(/(?<=[.!?])\s+/);
    return sentences.slice(0, 2).join(' ');
  }

  if (rawTech) {
    const clean = cleanCustomerText(rawTech, finding);
    const sentences = clean.split(/(?<=[.!?])\s+/);
    return sentences.slice(0, 2).join(' ');
  }

  // Deterministic summary from real properties
  const isKev = finding.detail?.threat_intelligence?.kev_listed;
  const epss = finding.detail?.threat_intelligence?.epss_score;
  const isInternet = finding.internet_exposure === true;
  const vulnName = finding.vulnerability_name || 'Vulnerability';
  const assetName = finding.detail?.asset_context?.asset_name || 'asset';

  if (isKev && isInternet) {
    return `Known-exploited vulnerability detected on internet-facing ${assetName} with active threat actor activity. Immediate patch or mitigation recommended.`;
  }
  if (isKev) {
    return `Cataloged in CISA Known Exploited Vulnerabilities (KEV). Poses elevated operational risk on ${assetName}.`;
  }
  if (epss && epss >= 0.5) {
    return `High probability of exploitation in the wild (${(epss * 100).toFixed(0)}% EPSS). Prioritize validation and remediation.`;
  }
  if (finding.risk_level === 'CRITICAL' || finding.risk_level === 'HIGH') {
    return `${vulnName} identified on critical infrastructure. Validate affected endpoints and apply vendor remediation.`;
  }

  return `Security finding on ${assetName} correlated across scanners. Review and schedule for standard remediation cycle.`;
}

/**
 * Formats confidence classification and numeric percentage.
 * Authoritative: NEVER re-interprets NEEDS_REVIEW as High Confidence.
 */
export function formatConfidence(finding) {
  const classification = (
    finding?.confidence_classification ||
    finding?.detail?.finding_confidence?.classification ||
    'HIGH_CONFIDENCE'
  ).toUpperCase();

  const rawScore = finding?.detail?.finding_confidence?.score;
  const pct = rawScore != null ? Math.round(rawScore * 100) : null;

  switch (classification) {
    case 'CONFIRMED':
      return {
        label: 'Confirmed',
        variant: 'teal',
        pct,
        badgeClass: 'ft-badge teal',
      };
    case 'HIGH_CONFIDENCE':
      return {
        label: 'High Confidence',
        variant: 'purple',
        pct,
        badgeClass: 'ft-badge purple',
      };
    case 'NEEDS_REVIEW':
      return {
        label: 'Needs Review',
        variant: 'amber',
        pct,
        badgeClass: 'ft-badge amber',
      };
    case 'LIKELY_NOISE':
      return {
        label: 'Likely Noise',
        variant: 'slate',
        pct,
        badgeClass: 'ft-badge slate',
      };
    case 'LOW_CONFIDENCE':
      return {
        label: 'Low Confidence',
        variant: 'slate',
        pct,
        badgeClass: 'ft-badge slate',
      };
    default:
      return {
        label: classification.replace(/_/g, ' '),
        variant: 'purple',
        pct,
        badgeClass: 'ft-badge purple',
      };
  }
}

/**
 * Formats SLA status and humanized due time.
 * If awaiting review, does NOT misleadingly show "SLA On Track".
 */
export function formatSla(finding) {
  const workflow = finding?.workflow || {};
  const status = (workflow.status || 'OPEN').toUpperCase();
  const slaStatus = (workflow.sla_status || 'ON_TRACK').toUpperCase();
  const confidence = (
    finding?.confidence_classification ||
    finding?.detail?.finding_confidence?.classification ||
    ''
  ).toUpperCase();

  // If pending analyst validation / review
  if (status === 'PENDING_REVIEW' || slaStatus === 'PENDING_REVIEW' || confidence === 'NEEDS_REVIEW') {
    return {
      label: 'SLA: Pending Review',
      timeText: 'Awaiting analyst review',
      state: 'PENDING_REVIEW',
      className: 'f-sla-tag pending-review',
    };
  }

  if (slaStatus === 'BREACHED') {
    return {
      label: 'SLA: Breached 🚫',
      timeText: formatDueTime(workflow.sla_due_at, workflow.sla_hours, true),
      state: 'BREACHED',
      className: 'f-sla-tag breached',
    };
  }

  if (slaStatus === 'AT_RISK') {
    return {
      label: 'SLA: At Risk ⚠',
      timeText: formatDueTime(workflow.sla_due_at, workflow.sla_hours),
      state: 'AT_RISK',
      className: 'f-sla-tag at-risk',
    };
  }

  if (slaStatus === 'MET') {
    return {
      label: 'SLA: Met ✓',
      timeText: 'Remediation completed',
      state: 'MET',
      className: 'f-sla-tag met',
    };
  }

  // Default: On Track
  return {
    label: 'SLA: On Track ✓',
    timeText: formatDueTime(workflow.sla_due_at, workflow.sla_hours),
    state: 'ON_TRACK',
    className: 'f-sla-tag on-track',
  };
}

/**
 * Computes human-friendly SLA due time
 */
export function formatDueTime(dueAt, slaHours, isBreached = false) {
  if (dueAt) {
    const dueTime = new Date(dueAt).getTime();
    if (!isNaN(dueTime)) {
      const now = Date.now();
      const diffMs = dueTime - now;
      if (diffMs < 0) {
        const absDiff = Math.abs(diffMs);
        const hours = Math.floor(absDiff / (1000 * 60 * 60));
        const mins = Math.floor((absDiff % (1000 * 60 * 60)) / (1000 * 60));
        return `Breached ${hours}h ${mins}m ago`;
      }
      const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const mins = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
      if (days >= 2) return `Due in ${days}d ${hours}h`;
      if (hours >= 1) return `Due in ${hours}h ${mins}m`;
      return `Due in ${mins}m`;
    }
  }

  if (slaHours != null) {
    if (slaHours >= 48) {
      const days = Math.floor(slaHours / 24);
      return `Due in ~${days}d`;
    }
    return `Due in ~${slaHours}h`;
  }

  return 'Due in 24h';
}

/**
 * Formats asset presentation hierarchy.
 * Guaranteed never to duplicate "ASSET-XXX • ASSET-XXX".
 */
export function formatAssetDisplay(finding) {
  const assetId = (finding?.asset_id || '').trim();
  const contextName = (finding?.detail?.asset_context?.asset_name || '').trim();
  const directName = (finding?.asset_name || '').trim();
  const host = (finding?.detail?.asset_context?.host || finding?.target_host || finding?.host || '').trim();

  let primaryName = '';
  let secondaryId = '';

  if (contextName && contextName !== assetId && !contextName.startsWith('host-') && contextName !== 'Unresolved Asset') {
    primaryName = contextName;
    secondaryId = assetId || host;
  } else if (directName && directName !== assetId && !directName.startsWith('host-')) {
    primaryName = directName;
    secondaryId = assetId || host;
  } else if (host) {
    primaryName = assetId ? 'Unresolved Asset' : 'Unmapped Asset';
    secondaryId = assetId ? `${assetId} (${host})` : host;
  } else if (assetId) {
    primaryName = 'Registered Asset';
    secondaryId = assetId;
  } else {
    primaryName = 'Unmapped Asset';
    secondaryId = 'No host identifier';
  }

  return { primaryName, secondaryId };
}

/**
 * Formats CVE identifier.
 */
export function formatCve(cveId) {
  if (cveId && typeof cveId === 'string' && cveId.toUpperCase().startsWith('CVE-')) {
    return {
      text: cveId.toUpperCase(),
      isAssigned: true,
    };
  }
  return {
    text: 'No CVE assigned',
    isAssigned: false,
  };
}

/**
 * Stripe indicator color on card left edge
 */
export function getStripeColor(score, rank, level) {
  const lvl = (level || '').toUpperCase();
  const num = typeof score === 'number' ? score : 0;

  if (lvl === 'CRITICAL' || num >= 90) return '#EF4444'; // Red
  if (lvl === 'HIGH' || num >= 60) return '#F97316';     // Orange
  if (lvl === 'MEDIUM' || num >= 30) return '#EAB308';   // Amber
  return '#10B981';                                      // Emerald Green
}
