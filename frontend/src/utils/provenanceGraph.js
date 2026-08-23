/**
 * provenanceGraph.js — Finding Provenance Graph for RizIntel
 *
 * DESIGN:
 * ─────────────────────────────────────────────────────────────
 * Each finding is represented as a directed graph (adjacency list).
 * Nodes represent entities: Finding, Scanner, CVE, Asset,
 *   ThreatIntel, RiskAssessment, Explanation, Ticket.
 * Edges represent relationships (e.g. "detected_by", "affects", "scored_by").
 *
 * Traversal complexity: O(V + E)
 *   V = number of nodes
 *   E = number of edges
 *
 * BFS — used for Finding Journey (level-by-level stage trace)
 * DFS — used for Risk DNA (deep factor decomposition)
 *
 * This enables complete decision traceability:
 *   Scanner alert → Deduplication → Confidence → Threat Intel
 *   → Risk Score → Explanation → Remediation Ticket
 * ─────────────────────────────────────────────────────────────
 */

/**
 * buildProvenanceGraph — builds an adjacency-list graph from a finding.
 * Returns { nodes: Map<id, NodeData>, edges: Map<id, string[]> }
 */
export function buildProvenanceGraph(finding) {
  if (!finding) return { nodes: new Map(), edges: new Map() };

  const nodes = new Map();
  const edges = new Map();

  const addNode = (id, type, label, data = {}) => {
    nodes.set(id, { id, type, label, data });
    if (!edges.has(id)) edges.set(id, []);
  };

  const addEdge = (from, to, relation = '') => {
    if (!edges.has(from)) edges.set(from, []);
    edges.get(from).push({ to, relation });
  };

  // Root node — the deduplicated finding
  const rootId = finding.finding_id;
  addNode(rootId, 'finding', finding.vulnerability_name, {
    risk_score: finding.risk_score,
    risk_level: finding.risk_level,
    cve_id: finding.cve_id,
  });

  // Scanner source nodes
  const sourcefindings = finding.detail?.provenance?.source_findings ?? [];
  sourcefindings.forEach(sf => {
    const sid = sf.finding_id;
    addNode(sid, 'scanner', sf.scanner, { scanner: sf.scanner, original_id: sf.finding_id });
    addEdge(sid, rootId, 'deduplicated_into');
    addEdge(rootId, sid, 'sourced_from');
  });

  // CVE node
  if (finding.cve_id) {
    const cveId = `CVE_${finding.cve_id}`;
    addNode(cveId, 'cve', finding.cve_id, { cve_id: finding.cve_id });
    addEdge(rootId, cveId, 'maps_to');
  }

  // Asset node
  const assetId = `ASSET_${finding.asset_id}`;
  addNode(assetId, 'asset', finding.detail?.asset_context?.asset_name ?? finding.asset_id, {
    criticality: finding.asset_criticality,
    environment: finding.detail?.asset_context?.environment,
    internet_facing: finding.internet_exposure,
    data_sensitivity: finding.detail?.asset_context?.data_sensitivity,
  });
  addEdge(rootId, assetId, 'affects');

  // Threat intelligence node
  const tiId = `TI_${rootId}`;
  const ti = finding.detail?.threat_intelligence ?? {};
  addNode(tiId, 'threat_intel', 'Threat Intelligence', {
    cvss: ti.cvss_score,
    epss: ti.epss_score,
    kev: ti.kev_listed,
    exploit: ti.exploit_available,
  });
  addEdge(rootId, tiId, 'enriched_by');

  // Risk assessment node
  const raId = `RA_${rootId}`;
  const ra = finding.detail?.risk_assessment ?? {};
  addNode(raId, 'risk_assessment', 'Risk Assessment (M5)', {
    score: finding.risk_score,
    level: finding.risk_level,
    breakdown: ra.score_breakdown,
    version: ra.scoring_version,
  });
  addEdge(rootId, raId, 'scored_by');

  // Explanation node
  const exId = `EX_${rootId}`;
  const ex = finding.detail?.explanation ?? {};
  addNode(exId, 'explanation', 'Explanation (M6)', {
    technical: ex.technical,
    management: ex.management,
    drivers: ex.top_risk_drivers,
  });
  addEdge(raId, exId, 'explained_by');

  // Remediation / ticket node
  const wf = finding.workflow ?? {};
  if (wf.ticket_id) {
    const ticketId = `TICKET_${wf.ticket_id}`;
    addNode(ticketId, 'ticket', wf.ticket_id, {
      status: wf.status,
      owner: wf.assigned_to,
      sla_status: wf.sla_status,
      sla_due_at: wf.sla_due_at,
    });
    addEdge(rootId, ticketId, 'remediated_by');
  }

  return { nodes, edges };
}

/**
 * bfsTraversal — breadth-first traversal of the provenance graph.
 * Returns ordered array of node IDs reachable from startId.
 * O(V + E)
 */
export function bfsTraversal(startId, edges) {
  const visited = new Set();
  const queue = [startId];
  const order = [];
  visited.add(startId);

  while (queue.length > 0) {
    const current = queue.shift();
    order.push(current);
    const neighbours = edges.get(current) ?? [];
    for (const { to } of neighbours) {
      if (!visited.has(to)) {
        visited.add(to);
        queue.push(to);
      }
    }
  }
  return order;
}

/**
 * dfsTraversal — depth-first traversal.
 * Returns ordered array of node IDs.
 * O(V + E)
 */
export function dfsTraversal(startId, edges, visited = new Set(), order = []) {
  if (visited.has(startId)) return order;
  visited.add(startId);
  order.push(startId);
  const neighbours = edges.get(startId) ?? [];
  for (const { to } of neighbours) {
    dfsTraversal(to, edges, visited, order);
  }
  return order;
}

/**
 * getNodesByType — filter nodes by type for Risk DNA display.
 */
export function getNodesByType(nodes, type) {
  return [...nodes.values()].filter(n => n.type === type);
}

/**
 * buildRiskDNANodes — creates React Flow node/edge arrays for Risk DNA graph.
 * Layout: center = risk score, 4 clusters = categories
 */
export function buildRiskDNANodes(finding) {
  if (!finding) return { rfNodes: [], rfEdges: [] };

  const ti = finding.detail?.threat_intelligence ?? {};
  const ac = finding.detail?.asset_context ?? {};
  const sc = finding.detail?.scanner_consensus ?? {};
  const fc = finding.detail?.finding_confidence ?? {};
  const wf = finding.workflow ?? {};
  const rb = finding.detail?.risk_assessment?.score_breakdown ?? {};

  const rfNodes = [];
  const rfEdges = [];

  const centerX = 440;
  const centerY = 200;

  // Center node — Risk Score
  rfNodes.push({
    id: 'CENTER',
    type: 'riskDNANode',
    position: { x: centerX - 60, y: centerY - 40 },
    data: {
      category: 'Risk Score (M5)',
      label: `${finding.risk_score}`,
      value: finding.risk_level,
      nodeClass: 'center-node',
    },
    draggable: false,
  });

  // ── Threat Intelligence cluster (top-left) ────────────────
  const tiNodes = [
    { id: 'TI_CVSS', label: 'CVSS Score', value: ti.cvss_score ?? 'N/A', x: 60, y: 20 },
    { id: 'TI_EPSS', label: 'EPSS Score', value: `${((ti.epss_score ?? 0) * 100).toFixed(0)}%`, x: 60, y: 90 },
    { id: 'TI_KEV', label: 'CISA KEV', value: ti.kev_listed ? 'Listed ⚠' : 'Not Listed', x: 60, y: 160 },
    { id: 'TI_EXPLOIT', label: 'Exploit', value: ti.exploit_available ? 'Available ⚠' : 'None', x: 60, y: 230 },
  ];
  tiNodes.forEach(n => {
    rfNodes.push({
      id: n.id, type: 'riskDNANode', position: { x: n.x, y: n.y },
      data: { category: 'Threat Intelligence', label: n.label, value: n.value, nodeClass: 'threat-intel' }, draggable: false
    });
    rfEdges.push({
      id: `e-${n.id}`, source: n.id, target: 'CENTER', type: 'smoothstep',
      style: { stroke: '#FECACA', strokeWidth: 1.5 }, animated: ti.kev_listed || ti.exploit_available
    });
  });

  // ── Asset Context cluster (top-right) ─────────────────────
  const acNodes = [
    { id: 'AC_CRIT', label: 'Asset Criticality', value: ac.criticality ?? finding.asset_criticality ?? 'N/A', x: 720, y: 20 },
    { id: 'AC_ENV', label: 'Environment', value: ac.environment ?? 'N/A', x: 720, y: 90 },
    { id: 'AC_NET', label: 'Internet Exposure', value: ac.internet_facing ? 'Yes ⚠' : 'Internal', x: 720, y: 160 },
    { id: 'AC_DATA', label: 'Data Sensitivity', value: ac.data_sensitivity ?? 'N/A', x: 720, y: 230 },
  ];
  acNodes.forEach(n => {
    rfNodes.push({
      id: n.id, type: 'riskDNANode', position: { x: n.x, y: n.y },
      data: { category: 'Asset Context', label: n.label, value: n.value, nodeClass: 'asset-ctx' }, draggable: false
    });
    rfEdges.push({
      id: `e-${n.id}`, source: n.id, target: 'CENTER', type: 'smoothstep',
      style: { stroke: '#BFDBFE', strokeWidth: 1.5 }, animated: false
    });
  });

  // ── Evidence cluster (bottom-left) ────────────────────────
  const evNodes = [
    { id: 'EV_SCANNERS', label: 'Scanners', value: (sc.scanner_names ?? []).join(', ') || 'N/A', x: 120, y: 330 },
    { id: 'EV_CONSENSUS', label: 'Consensus Score', value: `${((sc.score ?? 0) * 100).toFixed(0)}%`, x: 120, y: 400 },
    { id: 'EV_CONF', label: 'Confidence', value: fc.classification ?? 'N/A', x: 120, y: 470 },
  ];
  evNodes.forEach(n => {
    rfNodes.push({
      id: n.id, type: 'riskDNANode', position: { x: n.x, y: n.y },
      data: { category: 'Evidence', label: n.label, value: n.value, nodeClass: 'evidence' }, draggable: false
    });
    rfEdges.push({
      id: `e-${n.id}`, source: n.id, target: 'CENTER', type: 'smoothstep',
      style: { stroke: '#BBF7D0', strokeWidth: 1.5 }, animated: false
    });
  });

  // ── Remediation cluster (bottom-right) ───────────────────
  const remNodes = [
    { id: 'REM_SLA', label: 'SLA Status', value: wf.sla_status ?? 'N/A', x: 660, y: 330 },
    { id: 'REM_TICKET', label: 'Ticket', value: wf.ticket_id ?? 'N/A', x: 660, y: 400 },
    { id: 'REM_STATUS', label: 'Work Status', value: wf.status ?? 'N/A', x: 660, y: 470 },
  ];
  remNodes.forEach(n => {
    rfNodes.push({
      id: n.id, type: 'riskDNANode', position: { x: n.x, y: n.y },
      data: { category: 'Remediation', label: n.label, value: n.value, nodeClass: 'remediation' }, draggable: false
    });
    rfEdges.push({
      id: `e-${n.id}`, source: n.id, target: 'CENTER', type: 'smoothstep',
      style: { stroke: '#FDE68A', strokeWidth: 1.5 }, animated: false
    });
  });

  return { rfNodes, rfEdges };
}

/**
 * buildDecisionProvenanceChain — builds the 8-stage decision provenance graph for RizTrace.
 *
 * Stages:
 *   1. Scanner Ingestion
 *   2. Deduplication & Consensus
 *   3. Noise Filter & Confidence
 *   4. Threat Intel & Asset Context
 *   5. Dynamic Risk Score
 *   6. Explainability Rationale
 *   7. SLA & Remediation
 *   8. Analyst Decision
 *
 * Returns { nodes: Map, edges: Map, bfsOrder: string[], dfsOrder: string[] }
 */
export function buildDecisionProvenanceChain(finding, feedbackHistory = []) {
  if (!finding) {
    return { nodes: new Map(), edges: new Map(), bfsOrder: [], dfsOrder: [] };
  }

  const nodes = new Map();
  const edges = new Map();

  const addNode = (id, stageIndex, title, category, status, summary, details = {}) => {
    nodes.set(id, {
      id,
      stageIndex,
      title,
      category,
      status, // 'AVAILABLE' | 'NOT_AVAILABLE' | 'PENDING'
      summary,
      details,
    });
    if (!edges.has(id)) edges.set(id, []);
  };

  const addEdge = (from, to, relation) => {
    if (!edges.has(from)) edges.set(from, []);
    edges.get(from).push({ to, relation });
  };

  const prov = finding.detail?.provenance ?? {};
  const sc = finding.detail?.scanner_consensus ?? {};
  const fc = finding.detail?.finding_confidence ?? {};
  const ti = finding.detail?.threat_intelligence ?? {};
  const ac = finding.detail?.asset_context ?? {};
  const ra = finding.detail?.risk_assessment ?? {};
  const ex = finding.detail?.explanation ?? {};
  const wf = finding.workflow ?? {};

  // Stage 1: Scanner Ingestion
  const sourceFindings = prov.source_findings ?? [];
  const hasScanners = sourceFindings.length > 0 || (sc.scanner_names && sc.scanner_names.length > 0);
  // Use scanner names only for the summary text; show finding IDs in the details
  const scannerNames = sourceFindings.length > 0
    ? sourceFindings.map(s => s.scanner)
    : (sc.scanner_names ?? []);
  // Finding IDs for the "Source Findings" detail chips
  const sourceFindingIds = sourceFindings.length > 0
    ? sourceFindings.map(s => s.finding_id).filter(Boolean)
    : [];

  addNode(
    'stage_scanner',
    1,
    'Scanner Ingestion',
    'Ingestion',
    hasScanners ? 'AVAILABLE' : 'NOT_AVAILABLE',
    hasScanners
      ? `Ingested from ${scannerNames.join(', ')}`
      : 'No raw scanner alerts attached',
    {
      source_scanners: scannerNames,
      source_findings: sourceFindingIds.length > 0 ? sourceFindingIds : (hasScanners ? scannerNames : []),
      sourceFindingIds: sourceFindingIds,
      total_sources: (sourceFindingIds.length || scannerNames.length),
      first_detected: prov.first_detected ?? finding.created_at ?? 'N/A'
    }
  );

  // Stage 2: Deduplication & Consensus
  const hasDedup = sc.detected_by_count != null || sc.total_scanners != null;
  addNode(
    'stage_deduplication',
    2,
    'Deduplication & Consensus',
    'Correlation',
    hasDedup ? 'AVAILABLE' : 'NOT_AVAILABLE',
    hasDedup
      ? `${sc.detected_by_count ?? 0} of ${sc.total_scanners ?? 3} scanners correlated (${((sc.score ?? 0) * 100).toFixed(0)}% consensus)`
      : 'Deduplication metadata not available',
    {
      finding_id: finding.finding_id,
      detected_by_count: sc.detected_by_count ?? 0,
      total_scanners: sc.total_scanners ?? 3,
      consensus_score: sc.score != null ? `${(sc.score * 100).toFixed(0)}%` : 'N/A',
      correlated_scanners: sc.scanner_names ?? scannerNames ?? []
    }
  );
  addEdge('stage_scanner', 'stage_deduplication', 'deduplicated_into');

  // Stage 3: Noise Filter & Confidence
  const hasConfidence = fc.classification != null || fc.score != null;
  addNode(
    'stage_confidence',
    3,
    'Noise Filter & Confidence',
    'Validation',
    hasConfidence ? 'AVAILABLE' : 'NOT_AVAILABLE',
    hasConfidence
      ? `Classification: ${fc.classification ?? 'CONFIRMED'} (${((fc.score ?? 0.96) * 100).toFixed(0)}% Confidence)`
      : 'Confidence classification not available',
    {
      classification: fc.classification ?? finding.confidence_classification ?? 'N/A',
      confidence_score: fc.score != null ? `${(fc.score * 100).toFixed(0)}%` : 'N/A',
      noise_filter_status: 'Passed (No suppression triggers)'
    }
  );
  addEdge('stage_deduplication', 'stage_confidence', 'evaluated_confidence');

  // Stage 4: Threat Intel & Asset Context
  const cvssScore = ti.cvss_score != null ? ti.cvss_score : 'N/A';
  const epssVal = ti.epss_score != null ? `${(ti.epss_score * 100).toFixed(0)}%` : 'N/A';
  const criticalityVal = ac.criticality ?? finding.asset_criticality ?? 'N/A';
  addNode(
    'stage_threat_asset',
    4,
    'Threat Intel & Asset Context',
    'Enrichment',
    'AVAILABLE',
    `CVSS Score: ${cvssScore} | EPSS: ${epssVal} | Criticality: ${criticalityVal}`,
    {
      cvss_score: cvssScore,
      epss_score: epssVal,
      cisa_kev: ti.kev_listed ? 'Listed (Actively Exploited) ⚠' : 'Not Listed',
      exploit_available: ti.exploit_available ? 'Public Exploit Available ⚠' : 'None',
      asset_id: finding.asset_id,
      asset_name: ac.asset_name ?? finding.asset_id,
      criticality: criticalityVal,
      environment: ac.environment ?? 'Production',
      internet_facing: finding.internet_exposure !== false ? 'Yes (Internet-Facing)' : 'Internal',
      data_sensitivity: ac.data_sensitivity ?? 'N/A'
    }
  );
  addEdge('stage_confidence', 'stage_threat_asset', 'enriched_by');

  // Stage 5: Risk Score
  addNode(
    'stage_risk_score',
    5,
    'Dynamic Risk Score',
    'Prioritization',
    'AVAILABLE',
    `Calculated Score: ${finding.risk_score} / 100 (${finding.risk_level ?? 'HIGH'})`,
    {
      risk_score: finding.risk_score,
      risk_level: finding.risk_level,
      scoring_version: ra.scoring_version ?? 'M5 Engine',
      score_breakdown: ra.score_breakdown ?? {}
    }
  );
  addEdge('stage_threat_asset', 'stage_risk_score', 'scored_by');

  // Stage 6: Explainability Rationale
  const hasExplanation = ex.technical || ex.management || (ex.top_risk_drivers && ex.top_risk_drivers.length > 0);
  addNode(
    'stage_explanation',
    6,
    'Explainability Rationale',
    'Explainability',
    hasExplanation ? 'AVAILABLE' : 'NOT_AVAILABLE',
    hasExplanation
      ? (ex.technical ?? ex.management ?? 'Technical risk drivers compiled')
      : 'AI explanation not generated for this finding',
    {
      technical_explanation: ex.technical ?? 'N/A',
      management_summary: ex.management ?? 'N/A',
      top_risk_drivers: ex.top_risk_drivers ?? ['CVSS Severity', 'Asset Exposure']
    }
  );
  addEdge('stage_risk_score', 'stage_explanation', 'explained_by');

  // Stage 7: SLA & Remediation
  const hasTicket = wf.ticket_id != null || wf.status != null;
  addNode(
    'stage_sla_remediation',
    7,
    'SLA & Remediation',
    'Governance',
    hasTicket ? 'AVAILABLE' : 'NOT_AVAILABLE',
    hasTicket
      ? `Ticket: ${wf.ticket_id ?? 'N/A'} | Assigned: ${wf.assigned_to ?? 'Unassigned'} | SLA: ${wf.sla_status ?? 'ON_TRACK'}`
      : 'No remediation ticket or SLA tracked',
    {
      ticket_id: wf.ticket_id ?? 'N/A',
      assigned_to: wf.assigned_to ?? 'Unassigned',
      sla_status: wf.sla_status ?? 'N/A',
      sla_due_at: wf.sla_due_at ?? 'N/A',
      escalation_level: wf.escalation_level ?? 0,
      work_status: wf.status ?? 'Open'
    }
  );
  addEdge('stage_explanation', 'stage_sla_remediation', 'remediated_by');

  // Stage 8: Analyst Decision
  const latestFeedback = feedbackHistory && feedbackHistory.length > 0 ? feedbackHistory[0] : null;
  const hasDecision = latestFeedback != null;

  addNode(
    'stage_analyst_decision',
    8,
    'Analyst Decision',
    'Human-in-the-Loop',
    hasDecision ? 'AVAILABLE' : 'PENDING',
    hasDecision
      ? `${(latestFeedback.analyst_decision ?? '').replace(/_/g, ' ')} ${latestFeedback.reason ? `— "${latestFeedback.reason}"` : ''}`
      : 'Pending Analyst Review (Default algorithmic score active)',
    {
      decision: latestFeedback?.analyst_decision ?? 'PENDING',
      reason: latestFeedback?.reason ?? 'No analyst rationale recorded',
      timestamp: latestFeedback?.timestamp ? new Date(latestFeedback.timestamp).toLocaleString() : 'Pending',
      history_count: feedbackHistory ? feedbackHistory.length : 0
    }
  );
  addEdge('stage_sla_remediation', 'stage_analyst_decision', 'confirmed_by');

  const bfsOrder = bfsTraversal('stage_scanner', edges);
  const dfsOrder = dfsTraversal('stage_scanner', edges);

  return { nodes, edges, bfsOrder, dfsOrder };
}

export const buildDecisionProvenanceGraph = buildDecisionProvenanceChain;

