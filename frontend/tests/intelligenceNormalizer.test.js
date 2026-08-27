import { describe, it, expect } from 'vitest';
import { normalizeSecurityIntelligence } from '../src/utils/intelligenceNormalizer';

describe('Security Intelligence Analytics Normalizer — FIX 1-6 Tests', () => {
  const sampleFindings = [
    {
      finding_id: 'DEDUP-90626421',
      vulnerability_name: 'Apache Log4j Remote Code Execution (Log4Shell)',
      cve_id: 'CVE-2021-44228',
      asset_id: 'ASSET-PAY-001',
      risk_score: 68,
      risk_level: 'HIGH',
      confidence_classification: 'HIGH_CONFIDENCE',
      internet_exposure: true,
      asset_criticality: 'HIGH',
      detail: {
        threat_intelligence: { kev_listed: true, exploit_available: false, epss_score: 0.97 },
        asset_context: { criticality: 'HIGH', internet_facing: true },
        scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['Nuclei'] },
        audit_history: [{ analyst_action: 'ACCEPT_PRIORITY' }]
      }
    },
    {
      finding_id: 'DEDUP-05C0BE11',
      vulnerability_name: 'Spring Framework RCE (Spring4Shell)',
      cve_id: 'CVE-2022-22965',
      asset_id: 'ASSET-PAY-001',
      risk_score: 68,
      risk_level: 'HIGH',
      confidence_classification: 'HIGH_CONFIDENCE',
      internet_exposure: true,
      asset_criticality: 'HIGH',
      detail: {
        threat_intelligence: { kev_listed: true, exploit_available: false, epss_score: 0.89 },
        asset_context: { criticality: 'HIGH', internet_facing: true },
        scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['Nuclei'] }
      }
    },
    {
      finding_id: 'DEDUP-F21924A4',
      vulnerability_name: 'SQL Injection',
      cve_id: 'CVE-2023-0001',
      asset_id: 'ASSET-PAY-001',
      risk_score: 30,
      risk_level: 'MEDIUM',
      confidence_classification: 'NEEDS_REVIEW',
      internet_exposure: true,
      asset_criticality: 'HIGH',
      detail: {
        threat_intelligence: { kev_listed: false, exploit_available: false, epss_score: 0.05 },
        asset_context: { criticality: 'HIGH', internet_facing: true },
        scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['ZAP'] }
      }
    },
    {
      finding_id: 'DEDUP-7E64BD1F',
      vulnerability_name: 'X-Content-Type-Options Header Missing',
      asset_id: 'ASSET-PAY-001',
      risk_score: 30,
      risk_level: 'MEDIUM',
      confidence_classification: 'NEEDS_REVIEW',
      internet_exposure: true,
      asset_criticality: 'HIGH',
      detail: {
        threat_intelligence: { kev_listed: false },
        asset_context: { criticality: 'HIGH', internet_facing: true },
        scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['Wapiti'] }
      }
    },
    {
      finding_id: 'DEDUP-E8CB57B1',
      vulnerability_name: 'SQL Injection & Database Parameter Validation',
      asset_id: 'ASSET-PAY-001',
      risk_score: 35,
      risk_level: 'MEDIUM',
      confidence_classification: 'HIGH_CONFIDENCE',
      internet_exposure: true,
      asset_criticality: 'HIGH',
      detail: {
        threat_intelligence: { kev_listed: false },
        asset_context: { criticality: 'HIGH', internet_facing: true },
        scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['Nuclei'] }
      }
    },
    {
      finding_id: 'DEDUP-A3CFACE4',
      vulnerability_name: 'SQL Injection in Payment Gateway',
      asset_id: 'ASSET-PAY-001',
      risk_score: 30,
      risk_level: 'MEDIUM',
      confidence_classification: 'NEEDS_REVIEW',
      internet_exposure: true,
      asset_criticality: 'HIGH',
      detail: {
        threat_intelligence: { kev_listed: false },
        asset_context: { criticality: 'HIGH', internet_facing: true },
        scanner_consensus: { detected_by_count: 1, total_scanners: 3, scanner_names: ['ZAP'] }
      }
    }
  ];

  const sampleTasks = [
    {
      ticket_id: 'TCK-22F4EDB43C',
      finding_id: 'DEDUP-90626421',
      status: 'RESOLVED',
      priority: 'MEDIUM',
      assigned_to: 'secops',
      assignee_display_name: 'SOC Operations Team'
    }
  ];

  it('FIX 1: separates KEV membership from public exploit availability without contradiction', () => {
    const result = normalizeSecurityIntelligence({ findings: sampleFindings, tasks: sampleTasks });
    expect(result.snapshot.kevCount).toBe(2);
    expect(result.kevIntelligence.exploitAvailableCount).toBe(0);
    expect(result.kevIntelligence.publicExploitStatusText).toBe('Public exploit availability not identified');
    
    // Insight must NOT claim public exploit availability
    const kevInsight = result.currentInsights.find(i => i.id === 'kev-urgency');
    expect(kevInsight.title).toBe('KEV Catalog Correlation');
    expect(kevInsight.description).toContain('2 of 6 active findings are listed in the CISA Known Exploited Vulnerabilities catalog');
    expect(kevInsight.description).not.toContain('with known exploit availability');
  });

  it('FIX 1: handles missing public exploit field as information not available', () => {
    const findingsMissingExploit = [
      { finding_id: 'D-1', detail: { threat_intelligence: { kev_listed: true } } }
    ];
    const result = normalizeSecurityIntelligence({ findings: findingsMissingExploit });
    expect(result.kevIntelligence.publicExploitStatusText).toBe('Public exploit information not available');
  });

  it('FIX 2: workflow distribution reconciles exactly to declared population (3 Pending Review + 2 Open + 0 In Progress + 1 Resolved = 6)', () => {
    const result = normalizeSecurityIntelligence({ findings: sampleFindings, tasks: sampleTasks });
    const wf = result.workflowDistribution;
    expect(wf.total).toBe(6);
    expect(wf.pendingReview).toBe(3);
    expect(wf.open).toBe(2);
    expect(wf.inProgress).toBe(0);
    expect(wf.resolved).toBe(1);
    expect(wf.suppressed).toBe(0);

    const sum = wf.pendingReview + wf.open + wf.inProgress + wf.resolved + wf.suppressed;
    expect(sum).toBe(wf.total);
    expect(sum).toBe(6);
  });

  it('FIX 3: separates confidence classification, detection coverage, and analyst validation', () => {
    const result = normalizeSecurityIntelligence({ findings: sampleFindings, tasks: sampleTasks });
    const conf = result.confidenceDistribution;
    
    // Confidence classification
    expect(conf.highConfidence).toBe(3);
    expect(conf.needsReview).toBe(3);
    expect(conf.likelyNoise).toBe(0);

    // Detection coverage
    expect(conf.singleSourceCount).toBe(6);
    expect(conf.multiScannerCount).toBe(0);

    // Analyst validation
    expect(conf.analystConfirmed).toBe(1);
    expect(conf.pendingAnalystReview).toBe(5);
  });

  it('FIX 4: authoritative asset criticality preserves HIGH and does not convert to CRITICAL', () => {
    const result = normalizeSecurityIntelligence({ findings: sampleFindings, tasks: sampleTasks });
    expect(result.assetCriticalityDistribution.CRITICAL).toBe(0);
    expect(result.assetCriticalityDistribution.HIGH).toBe(6);
    expect(result.assetCriticalityDistribution.MEDIUM).toBe(0);
    expect(result.assetCriticalityDistribution.LOW).toBe(0);
    expect(result.intersections.highCriticalityAssetFindingCount).toBe(6);
  });

  it('FIX 5: computes true KEV + Internet-Facing set intersection without unsupported urgency wording', () => {
    const result = normalizeSecurityIntelligence({ findings: sampleFindings, tasks: sampleTasks });
    expect(result.intersections.kevExposedCount).toBe(2);
    expect(result.intersections.kevExposedIntersectionIds).toEqual(['DEDUP-90626421', 'DEDUP-05C0BE11']);
  });

  it('FIX 6: reconciles assignment, excludes resolved task from unassigned, and excludes review-blocked findings', () => {
    const result = normalizeSecurityIntelligence({ findings: sampleFindings, tasks: sampleTasks });
    // Out of 6 findings:
    // - 3 are NEEDS_REVIEW (review-blocked)
    // - 1 is DEDUP-90626421 (RESOLVED by TCK-22F4EDB43C / SOC Operations Team)
    // - 2 are OPEN and unassigned (Spring4Shell + SQL Injection & Parameter Validation)
    expect(result.workflowDistribution.unassignedEligibleCount).toBe(2);
  });
});
