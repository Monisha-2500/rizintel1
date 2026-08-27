import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import FindingsQueue from '../src/pages/FindingsQueue';
import * as findingsService from '../src/services/findingsService';
import {
  cleanCustomerText,
  formatConfidence,
  formatSla,
  formatAssetDisplay,
  formatCve,
  getWhyItMatters
} from '../src/utils/customerFacingText';

const mockCanonicalFindings = [
  {
    schema_version: '1.0',
    finding_id: 'DEDUP-B858594F',
    cve_id: null,
    asset_id: 'ASSET-DA1A14B2CF',
    vulnerability_name: 'SQL Injection',
    vulnerability_type: 'SQL_INJECTION',
    risk_score: 30,
    risk_level: 'MEDIUM',
    confidence_classification: 'NEEDS_REVIEW',
    asset_criticality: 'HIGH',
    internet_exposure: true,
    workflow: {
      status: 'PENDING_REVIEW',
      sla_status: 'PENDING_REVIEW',
      sla_hours: 720,
    },
    detail: {
      scanner_consensus: { score: 0.67, detected_by_count: 2, total_scanners: 3, scanner_names: ['NUCLEI', 'ZAP'] },
      finding_confidence: { score: 0.7325, classification: 'NEEDS_REVIEW' },
      threat_intelligence: { cvss_score: null, epss_score: null, kev_listed: false, exploit_available: false },
      asset_context: {
        asset_name: 'Payment Gateway Service (Web Application)',
        environment: 'PRODUCTION',
        criticality: 'HIGH',
        internet_facing: true,
      },
      explanation: {
        technical: 'SQL Injection on asset Payment Gateway Service was scored 30.0/100 (MEDIUM) by the risk engine (M5). Evidence: CISA KEV listed = False. Finding confidence: 0.7325 (CONFIDENCECLASSIFICATION.NEEDS_REVIEW).',
        management: 'A medium severity security issue (SQL Injection) was found on Payment Gateway Service.',
        top_risk_drivers: ['INTERNET_FACING', 'CRITICAL_ASSET'],
      },
    },
  },
  {
    schema_version: '1.0',
    finding_id: 'DEDUP-LOG4J-01',
    cve_id: 'CVE-2021-44228',
    asset_id: 'ASSET-AUTH-002',
    vulnerability_name: 'Apache Log4j Remote Code Execution',
    vulnerability_type: 'REMOTE_CODE_EXECUTION',
    risk_score: 95,
    risk_level: 'CRITICAL',
    confidence_classification: 'HIGH_CONFIDENCE',
    asset_criticality: 'CRITICAL',
    internet_exposure: true,
    workflow: {
      status: 'OPEN',
      sla_status: 'BREACHED',
      sla_due_at: '2026-08-20T12:00:00Z',
    },
    detail: {
      scanner_consensus: { score: 1.0, detected_by_count: 3, total_scanners: 3, scanner_names: ['ZAP', 'NUCLEI', 'WAPITI'] },
      finding_confidence: { score: 0.98, classification: 'HIGH_CONFIDENCE' },
      threat_intelligence: { cvss_score: 10.0, epss_score: 0.97, kev_listed: true, exploit_available: true },
      asset_context: {
        asset_name: 'Core Auth Gateway',
        environment: 'PRODUCTION',
        criticality: 'CRITICAL',
        internet_facing: true,
      },
      explanation: {
        technical: 'Log4Shell RCE scored 95/100 (CRITICAL) by the risk engine (M5). CISA KEV listed = True.',
        management: 'Critical zero-day vulnerability in logging framework.',
      },
    },
  },
];

describe('Findings SOC Queue Component & Utilities', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('Customer Facing Text Sanitization', () => {
    it('25. removes internal engine names (M1-M8)', () => {
      const raw = 'scored 68/100 (HIGH) by the risk engine (M5).';
      const clean = cleanCustomerText(raw);
      expect(clean).not.toContain('(M5)');
      expect(clean).toContain('Risk score: 68/100 · HIGH');
    });

    it('26. removes raw Python enum strings', () => {
      const raw = 'Confidence is CONFIDENCECLASSIFICATION.HIGH_CONFIDENCE and CONFIDENCECLASSIFICATION.NEEDS_REVIEW.';
      const clean = cleanCustomerText(raw);
      expect(clean).toContain('High Confidence');
      expect(clean).toContain('Needs Review');
      expect(clean).not.toContain('CONFIDENCECLASSIFICATION');
    });

    it('20. sanitizes raw booleans in explanations', () => {
      const raw = 'CISA KEV listed = False, exploit available = False, internet-facing = True';
      const clean = cleanCustomerText(raw);
      expect(clean).toContain('Not listed in CISA KEV');
      expect(clean).toContain('No public exploit available');
      expect(clean).toContain('Internet-facing');
      expect(clean).not.toContain('False');
    });

    it('23. NEEDS_REVIEW does NOT visually become High Confidence', () => {
      const conf = formatConfidence(mockCanonicalFindings[0]);
      expect(conf.label).toBe('Needs Review');
      expect(conf.variant).toBe('amber');
    });

    it('24. pending-review does not falsely show SLA On Track', () => {
      const sla = formatSla(mockCanonicalFindings[0]);
      expect(sla.label).toBe('SLA: Pending Review');
      expect(sla.label).not.toContain('On Track');
      expect(sla.state).toBe('PENDING_REVIEW');
    });

    it('27. formats asset display without repeating asset ID', () => {
      const asset = formatAssetDisplay(mockCanonicalFindings[0]);
      expect(asset.primaryName).toBe('Payment Gateway Service (Web Application)');
      expect(asset.secondaryId).toBe('ASSET-DA1A14B2CF');
      expect(asset.primaryName).not.toEqual(asset.secondaryId);
    });

    it('16. formats unassigned CVE cleanly', () => {
      const cve = formatCve(null);
      expect(cve.text).toBe('No CVE assigned');
      expect(cve.isAssigned).toBe(false);
    });

    it('17. formats unmapped asset cleanly when name is missing', () => {
      const asset = formatAssetDisplay({ asset_id: 'ASSET-UNKNOWN', target_host: '10.0.0.5:8080' });
      expect(asset.primaryName).toBe('Unresolved Asset');
      expect(asset.secondaryId).toBe('ASSET-UNKNOWN (10.0.0.5:8080)');
    });
  });

  describe('FindingsQueue Page Integration', () => {
    it('1. displays loading skeleton state before data resolves', () => {
      vi.spyOn(findingsService, 'getFindings').mockImplementation(() => new Promise(() => {}));
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );
      expect(screen.getByLabelText(/loading findings/i)).toBeInTheDocument();
    });

    it('2. displays authentic error state on API failure (no mock fallback)', async () => {
      vi.spyOn(findingsService, 'getFindings').mockRejectedValue(new Error('Network timeout'));
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText(/Unable to load findings/i)).toBeInTheDocument();
      });
      expect(screen.getByText(/Network timeout/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument();
    });

    it('3. displays zero-findings empty state when organization has no findings', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue([]);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText(/No findings yet/i)).toBeInTheDocument();
      });
      expect(screen.getByText(/Completed security scans will appear here after analysis/i)).toBeInTheDocument();
    });

    it('5. renders real canonical findings with authentic metadata', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('Apache Log4j Remote Code Execution')).toBeInTheDocument();
        expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      });

      expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument();
      expect(screen.getByText('No CVE assigned')).toBeInTheDocument();
      expect(screen.getByText('Payment Gateway Service (Web Application)')).toBeInTheDocument();
      expect(screen.getByText('Core Auth Gateway')).toBeInTheDocument();
    });

    it('7. filters findings by search term', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('Apache Log4j Remote Code Execution')).toBeInTheDocument();
      });

      const searchInput = screen.getByPlaceholderText(/Search by finding, CVE, asset or host/i);
      fireEvent.change(searchInput, { target: { value: 'Log4j' } });

      await waitFor(() => {
        expect(screen.getByText('Apache Log4j Remote Code Execution')).toBeInTheDocument();
        expect(screen.queryByText('Payment Gateway Service (Web Application)')).not.toBeInTheDocument();
      });
    });

    it('8. filters findings by risk level', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      });

      const riskSelect = screen.getByLabelText(/Filter by severity/i);
      fireEvent.change(riskSelect, { target: { value: 'CRITICAL' } });

      await waitFor(() => {
        expect(screen.getByText('Apache Log4j Remote Code Execution')).toBeInTheDocument();
        expect(screen.queryByText('SQL Injection')).not.toBeInTheDocument();
      });
    });

    it('9. filters findings by confidence', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      });

      const confSelect = screen.getByLabelText(/Filter by confidence/i);
      fireEvent.change(confSelect, { target: { value: 'NEEDS_REVIEW' } });

      await waitFor(() => {
        expect(screen.getByText('SQL Injection')).toBeInTheDocument();
        expect(screen.queryByText('Apache Log4j Remote Code Execution')).not.toBeInTheDocument();
      });
    });

    it('14. displays scan run scope banner when navigated with scan_run_id', async () => {
      vi.spyOn(findingsService, 'getScanRunFindings').mockResolvedValue({
        findings: [mockCanonicalFindings[0]],
        scan_run_id: 'SR-2C5BAAB5FB91',
        asset_id: 'ASSET-DA1A14B2CF',
      });

      render(
        <MemoryRouter initialEntries={['/findings?scan_run_id=SR-2C5BAAB5FB91&org_id=ORG-RIZZOLVE-DEMO']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText(/Viewing findings for Scan Run/i)).toBeInTheDocument();
        expect(screen.getByText('SR-2C5BAAB5FB91')).toBeInTheDocument();
      });

      expect(screen.getByRole('button', { name: /Clear Filter|Clear scan run filter/i })).toBeInTheDocument();
    });

    it('19 & 20. renders KEV badge only when threat intelligence kev_listed is true', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText(/Known Exploited \(KEV\)/i)).toBeInTheDocument();
      });

      // Exactly 1 KEV badge rendered for the Log4j finding
      const kevBadges = screen.getAllByText(/Known Exploited \(KEV\)/i);
      expect(kevBadges).toHaveLength(1);
    });

    it('5. scanner consensus displays formatted "Detected by X of Y scanners"', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('Detected by 2 of 3 scanners')).toBeInTheDocument();
        expect(screen.getByText('Detected by 3 of 3 scanners')).toBeInTheDocument();
      });
    });

    it('1 & 2. synchronizes explanation with resolved asset and removes UNKNOWN-classified wording', () => {
      const rawExplanation = 'A high-risk security finding (Log4j) was identified on Unresolved Asset, which is a unknown asset. This system handles UNKNOWN-classified data.';
      const findingWithResolvedAsset = {
        ...mockCanonicalFindings[0],
        detail: {
          ...mockCanonicalFindings[0].detail,
          asset_context: {
            asset_name: 'Payment Gateway Service (Web Application)',
            criticality: 'HIGH',
          },
        },
      };

      const cleaned = cleanCustomerText(rawExplanation, findingWithResolvedAsset);
      expect(cleaned).toContain('Payment Gateway Service (Web Application)');
      expect(cleaned).toContain('which is a high asset');
      expect(cleaned).not.toContain('Unresolved Asset');
      expect(cleaned).not.toContain('UNKNOWN-classified data');
      expect(cleaned).not.toContain('which is a unknown asset');
    });

    it('1b. preserves truthful description for genuinely unresolved asset', () => {
      const rawExplanation = 'A medium-risk security finding (SQL Injection) was identified on Unresolved Asset, which is a unknown asset. This system handles UNKNOWN-classified data.';
      const unmappedFinding = {
        finding_id: 'DEDUP-UNMAPPED-01',
        asset_id: 'UNMAPPED',
        asset_criticality: 'UNKNOWN',
        detail: {
          asset_context: {
            asset_name: 'Unresolved Asset',
            criticality: 'UNKNOWN',
          },
        },
      };

      const cleaned = cleanCustomerText(rawExplanation, unmappedFinding);
      expect(cleaned).toContain('Unresolved Asset');
      expect(cleaned).toContain('which is currently unclassified in the asset registry');
      expect(cleaned).not.toContain('UNKNOWN-classified data');
      expect(cleaned).not.toContain('which is a unknown asset');
    });

    it('6. primary Investigate action button has accessible label and directs to finding details', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Investigate finding DEDUP-B858594F/i })).toBeInTheDocument();
      });
    });

    it('4. renders filter-empty state when filters match zero findings', async () => {
      vi.spyOn(findingsService, 'getFindings').mockResolvedValue(mockCanonicalFindings);
      render(
        <MemoryRouter initialEntries={['/findings']}>
          <Routes>
            <Route path="/findings" element={<FindingsQueue />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('SQL Injection')).toBeInTheDocument();
      });

      const searchInput = screen.getByPlaceholderText(/Search by finding, CVE, asset or host/i);
      fireEvent.change(searchInput, { target: { value: 'NON_EXISTENT_QUERY_STRING_XYZ' } });

      await waitFor(() => {
        expect(screen.getByText(/No findings match your filters/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Reset Filters/i })).toBeInTheDocument();
      });
    });
  });
});
