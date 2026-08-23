/**
 * assetsService.js — Asset-centric view data service.
 *
 * Derives asset summaries from mock_findings.json (grouped by asset_id).
 * Replace with GET /api/assets for live integration.
 */

import mockFindings from '../data/mock_findings.json';
import { getAssetDisplayName, getFindings } from './findingsService';

/**
 * getAssets — returns an array of asset summary objects.
 * Each asset contains aggregated vulnerability counts from active findings.
 */
export async function getAssets() {
  try {
    const findings = await getFindings();
    return deriveAssetsFromFindings(findings);
  } catch (err) {
    console.warn('Failed to retrieve findings for asset view, using mock fallback:', err);
    return deriveAssetsFromFindings(mockFindings);
  }
}

/**
 * deriveAssetsFromFindings — groups findings by asset_id and computes stats.
 * Pure function — can be unit tested independently.
 */
export function deriveAssetsFromFindings(findings) {
  if (!Array.isArray(findings)) return [];

  const assetMap = new Map();

  findings.forEach(f => {
    const assetId = f.asset_id;
    if (!assetId) return;

    if (!assetMap.has(assetId)) {
      const ac = f.detail?.asset_context ?? {};
      assetMap.set(assetId, {
        asset_id:         assetId,
        display_name:     getAssetDisplayName(assetId),
        environment:      ac.environment ?? 'UNKNOWN',
        criticality:      f.asset_criticality ?? ac.criticality ?? 'UNKNOWN',
        internet_facing:  f.internet_exposure ?? ac.internet_facing ?? false,
        data_sensitivity: ac.data_sensitivity ?? 'UNKNOWN',
        findings:         [],
        highest_risk:     0,
        critical_count:   0,
        high_count:       0,
        open_count:       0,
      });
    }

    const asset = assetMap.get(assetId);
    asset.findings.push(f);

    if ((f.risk_score ?? 0) > asset.highest_risk) {
      asset.highest_risk = f.risk_score;
    }
    if ((f.risk_level ?? '').toUpperCase() === 'CRITICAL') asset.critical_count++;
    if ((f.risk_level ?? '').toUpperCase() === 'HIGH')     asset.high_count++;
    if ((f.workflow?.status ?? '').toUpperCase() !== 'RESOLVED'
      && (f.workflow?.status ?? '').toUpperCase() !== 'CLOSED') {
      asset.open_count++;
    }
  });

  // Sort by highest risk descending
  return [...assetMap.values()].sort((a, b) => b.highest_risk - a.highest_risk);
}
