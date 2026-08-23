import { describe, it, expect } from 'vitest';
import { getMitreAttackContext, NOT_MAPPED, TECHNIQUE_CATALOG } from './mitreAttack';
import { buildProvenanceGraph, buildDecisionProvenanceGraph } from './provenanceGraph';
import { PriorityQueue, triageFindings } from './priorityQueue';

describe('MITRE ATT&CK Context Mapping (M8 Enrichment)', () => {
  it('maps SQL Injection finding to T1190 with HIGH confidence', () => {
    const finding = {
      finding_id: 'DEDUP-0001',
      title: 'SQL Injection in Payment Gateway',
      vulnerability_type: 'SQL Injection',
      risk_score: 94
    };
    const res = getMitreAttackContext(finding);
    expect(res.isMapped).toBe(true);
    expect(res.technique_id).toBe('T1190');
    expect(res.technique_name).toBe('Exploit Public-Facing Application');
    expect(res.tactic).toBe('Initial Access');
    expect(res.tactic_id).toBe('TA0001');
    expect(res.sub_technique).toBe('SQL Injection');
    expect(res.confidence).toBe('HIGH');
    expect(res.source).toBe('CVE Class + Vulnerability Pattern');
    expect(res.mitre_url).toContain('T1190');
  });

  it('maps XSS vulnerability to T1189 with MEDIUM confidence', () => {
    const finding = {
      finding_id: 'DEDUP-0002',
      vulnerability_type: 'Cross-Site Scripting (Reflected)',
      title: 'Reflected XSS on search endpoint'
    };
    const res = getMitreAttackContext(finding);
    expect(res.isMapped).toBe(true);
    expect(res.technique_id).toBe('T1189');
    expect(res.technique_name).toBe('Drive-by Compromise');
    expect(res.confidence).toBe('MEDIUM');
  });

  it('maps Remote Code Execution to T1059 with HIGH confidence', () => {
    const finding = {
      finding_id: 'DEDUP-0005',
      vulnerability_type: 'Remote Code Execution (RCE)',
      title: 'Unauthenticated RCE in Apache Log4j'
    };
    const res = getMitreAttackContext(finding);
    expect(res.isMapped).toBe(true);
    expect(res.technique_id).toBe('T1059');
    expect(res.tactic).toBe('Execution');
    expect(res.confidence).toBe('HIGH');
  });

  it('maps SSRF to T1090 Proxy technique', () => {
    const finding = {
      finding_id: 'DEDUP-0007',
      vulnerability_type: 'Server-Side Request Forgery (SSRF)',
      title: 'SSRF in Webhook Dispatcher'
    };
    const res = getMitreAttackContext(finding);
    expect(res.isMapped).toBe(true);
    expect(res.technique_id).toBe('T1090');
    expect(res.tactic).toBe('Command and Control');
  });

  it('gracefully returns NOT_MAPPED for unknown or generic findings', () => {
    const finding = {
      finding_id: 'DEDUP-9999',
      vulnerability_type: 'Generic Informational Banner Disclosure',
      title: 'Server version in header'
    };
    const res = getMitreAttackContext(finding);
    expect(res.isMapped).toBe(false);
    expect(res.technique_id).toBeNull();
    expect(res.rationale).toContain('No confident MITRE ATT&CK mapping');
  });

  it('handles null, undefined, empty, or malformed input without throwing', () => {
    expect(getMitreAttackContext(null)).toEqual(NOT_MAPPED);
    expect(getMitreAttackContext(undefined)).toEqual(NOT_MAPPED);
    expect(getMitreAttackContext({})).toEqual(NOT_MAPPED);
    expect(getMitreAttackContext({ title: 12345, detail: null })).toEqual(NOT_MAPPED);
  });

  it('catalog maintains complete structured metadata for all techniques', () => {
    expect(TECHNIQUE_CATALOG.length).toBeGreaterThanOrEqual(10);
    TECHNIQUE_CATALOG.forEach(entry => {
      expect(entry.keywords.length).toBeGreaterThan(0);
      expect(entry.technique_id).toMatch(/^T\d{4}/);
      expect(entry.technique_name).toBeTruthy();
      expect(entry.tactic).toBeTruthy();
      expect(entry.tactic_id).toMatch(/^TA\d{4}/);
      expect(['HIGH', 'MEDIUM', 'LOW']).toContain(entry.confidence);
      expect(entry.rationale).toBeTruthy();
      expect(entry.source).toBeTruthy();
      expect(entry.mitre_url).toContain('attack.mitre.org');
    });
  });
});

describe('RizTrace Provenance & Pipeline Traversal Graph', () => {
  const sampleFinding = {
    finding_id: 'DEDUP-0001',
    risk_score: 94,
    vulnerability_type: 'SQL Injection',
    detail: {
      provenance: {
        source_findings: [
          { finding_id: 'ZAP-001', scanner: 'OWASP ZAP' },
          { finding_id: 'NESSUS-001', scanner: 'Nessus Pro' }
        ],
        journey: [
          { stage: '1. Scanner Ingestion', status: 'COMPLETED' },
          { stage: '2. Deduplication', status: 'COMPLETED' }
        ]
      },
      scanner_consensus: {
        score: 95,
        scanner_names: ['ZAP', 'Nessus'],
        detected_by_count: 2,
        total_scanners: 3
      },
      finding_confidence: { score: 90, classification: 'CONFIRMED' },
      threat_intelligence: { cvss_score: 9.8, epss_score: 0.91, kev_listed: true, exploit_available: true },
      asset_context: {
        asset_name: 'Payment API',
        environment: 'PRODUCTION',
        criticality: 'TIER-1 CRITICAL',
        internet_facing: true,
        data_sensitivity: 'PCI-DSS'
      },
      risk_assessment: { score_breakdown: {}, scoring_version: 'M5.0' },
      explanation: { technical: 'Tech explanation', management: 'Exec summary' }
    },
    workflow: { ticket_id: 'VULN-0001', status: 'TRIAGED', sla_status: 'ON_TRACK' }
  };

  it('builds 8-stage decision provenance graph correctly', () => {
    const graph = buildDecisionProvenanceGraph(sampleFinding);
    expect(graph.nodes.size).toBe(8);
    expect(graph.bfsOrder.length).toBe(8);
    expect(graph.dfsOrder.length).toBe(8);

    // BFS is sequential Stage 1 -> Stage 8
    expect(graph.bfsOrder[0]).toBe('stage_scanner');
    expect(graph.bfsOrder[7]).toBe('stage_analyst_decision');

    // DFS is root traversal
    expect(graph.dfsOrder[0]).toBe('stage_scanner');
  });

  it('extracts source finding IDs rather than scanner names in Stage 1', () => {
    const graph = buildDecisionProvenanceGraph(sampleFinding);
    const stage1 = graph.nodes.get('stage_scanner');
    expect(stage1.details.sourceFindingIds).toEqual(['ZAP-001', 'NESSUS-001']);
  });
});

describe('Priority Queue Risk Triage', () => {
  it('correctly ranks findings by SLA urgency and M5 risk score', () => {
    const pq = new PriorityQueue();
    pq.insert({ finding_id: 'F1', risk_score: 50, sla_hours: 48 });
    pq.insert({ finding_id: 'F2', risk_score: 94, sla_hours: 4 });
    pq.insert({ finding_id: 'F3', risk_score: 75, sla_hours: 24 });

    const top = pq.peek();
    expect(top.finding_id).toBe('F2'); // highest urgency + risk

    const triaged = triageFindings([
      { finding_id: 'F1', risk_score: 50 },
      { finding_id: 'F2', risk_score: 94 },
      { finding_id: 'F3', risk_score: 75 }
    ]);
    expect(triaged[0].finding_id).toBe('F2');
    expect(triaged[1].finding_id).toBe('F3');
    expect(triaged[2].finding_id).toBe('F1');
  });
});
