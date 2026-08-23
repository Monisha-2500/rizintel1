import { describe, it, expect } from 'vitest';
import { buildDecisionProvenanceChain, bfsTraversal, dfsTraversal } from '../src/utils/provenanceGraph';

describe('RizTrace – Decision Provenance Graph', () => {
  const sampleFinding = {
    finding_id: 'DEDUP-0001',
    vulnerability_name: 'SQL Injection in Payment Gateway',
    cve_id: 'CVE-2024-1234',
    risk_score: 94,
    risk_level: 'CRITICAL',
    asset_id: 'ASSET-101',
    asset_criticality: 'CRITICAL',
    internet_exposure: true,
    detail: {
      provenance: {
        source_findings: [
          { finding_id: 'RAW-1', scanner: 'OWASP ZAP' },
          { finding_id: 'RAW-2', scanner: 'Qualys' }
        ],
        first_detected: '2026-08-18'
      },
      scanner_consensus: {
        detected_by_count: 2,
        total_scanners: 3,
        score: 0.67,
        scanner_names: ['OWASP ZAP', 'Qualys']
      },
      finding_confidence: {
        classification: 'CONFIRMED',
        score: 0.96
      },
      threat_intelligence: {
        cvss_score: 9.8,
        epss_score: 0.91,
        kev_listed: true,
        exploit_available: true
      },
      asset_context: {
        asset_name: 'Fee Payment API',
        criticality: 'Tier-1 Critical',
        environment: 'Production',
        data_sensitivity: 'PCI'
      },
      risk_assessment: {
        scoring_version: 'M5 v2.4',
        score_breakdown: { base: 80, KEV: 8, Exposure: 6 }
      },
      explanation: {
        technical: 'Known exploited vulnerability on critical payment endpoint.',
        management: 'Urgent patch required.',
        top_risk_drivers: ['CISA KEV Match', 'Internet Exposure', 'EPSS 91%']
      }
    },
    workflow: {
      ticket_id: 'VULN-0001',
      assigned_to: 'SecOps Team',
      sla_status: 'ON_TRACK',
      status: 'Open'
    }
  };

  it('should construct an 8-stage decision provenance graph', () => {
    const { nodes, edges, bfsOrder } = buildDecisionProvenanceChain(sampleFinding);
    
    expect(nodes.size).toBe(8);
    expect(bfsOrder.length).toBe(8);
    
    // Check all 8 stages are present
    expect(nodes.has('stage_scanner')).toBe(true);
    expect(nodes.has('stage_deduplication')).toBe(true);
    expect(nodes.has('stage_confidence')).toBe(true);
    expect(nodes.has('stage_threat_asset')).toBe(true);
    expect(nodes.has('stage_risk_score')).toBe(true);
    expect(nodes.has('stage_explanation')).toBe(true);
    expect(nodes.has('stage_sla_remediation')).toBe(true);
    expect(nodes.has('stage_analyst_decision')).toBe(true);
  });

  it('should traverse nodes in correct BFS ingestion sequence', () => {
    const { bfsOrder } = buildDecisionProvenanceChain(sampleFinding);
    
    expect(bfsOrder).toEqual([
      'stage_scanner',
      'stage_deduplication',
      'stage_confidence',
      'stage_threat_asset',
      'stage_risk_score',
      'stage_explanation',
      'stage_sla_remediation',
      'stage_analyst_decision'
    ]);
  });

  it('should preserve M5 risk score without recalculation', () => {
    const { nodes } = buildDecisionProvenanceChain(sampleFinding);
    const riskNode = nodes.get('stage_risk_score');
    
    expect(riskNode.details.risk_score).toBe(94);
    expect(riskNode.details.risk_level).toBe('CRITICAL');
  });

  it('should handle pending analyst review state when no feedback is recorded', () => {
    const { nodes } = buildDecisionProvenanceChain(sampleFinding, []);
    const analystNode = nodes.get('stage_analyst_decision');
    
    expect(analystNode.status).toBe('PENDING');
    expect(analystNode.summary).toContain('Pending Analyst Review');
  });

  it('should reflect analyst feedback decision when available', () => {
    const mockFeedback = [
      {
        analyst_decision: 'ACCEPT_PRIORITY',
        reason: 'Confirmed SLA urgency and payload exploitability.',
        timestamp: new Date().toISOString()
      }
    ];

    const { nodes } = buildDecisionProvenanceChain(sampleFinding, mockFeedback);
    const analystNode = nodes.get('stage_analyst_decision');
    
    expect(analystNode.status).toBe('AVAILABLE');
    expect(analystNode.summary).toContain('ACCEPT PRIORITY');
    expect(analystNode.details.decision).toBe('ACCEPT_PRIORITY');
    expect(analystNode.details.reason).toContain('Confirmed SLA urgency');
  });

  it('should handle graceful NOT_AVAILABLE states for incomplete findings', () => {
    const minimalFinding = {
      finding_id: 'MIN-001',
      risk_score: 50,
      risk_level: 'MEDIUM',
      asset_id: 'SERVER-01'
    };

    const { nodes } = buildDecisionProvenanceChain(minimalFinding);
    
    expect(nodes.get('stage_scanner').status).toBe('NOT_AVAILABLE');
    expect(nodes.get('stage_deduplication').status).toBe('NOT_AVAILABLE');
    expect(nodes.get('stage_confidence').status).toBe('NOT_AVAILABLE');
    expect(nodes.get('stage_explanation').status).toBe('NOT_AVAILABLE');
    expect(nodes.get('stage_sla_remediation').status).toBe('NOT_AVAILABLE');
    expect(nodes.get('stage_analyst_decision').status).toBe('PENDING');
    
    // Risk score and basic asset context remain available
    expect(nodes.get('stage_risk_score').status).toBe('AVAILABLE');
    expect(nodes.get('stage_risk_score').details.risk_score).toBe(50);
  });
});
