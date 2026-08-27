/**
 * capabilityNormalizer.js — Canonical Scanner Key & Availability Normalizer
 */

export function normalizeScannerKey(key) {
  if (!key || typeof key !== 'string') return null;
  const s = key.trim().toUpperCase().replace(/ /g, '_');
  if (s === 'NUCLEI') return 'NUCLEI';
  if (s === 'ZAP' || s === 'OWASP_ZAP' || s === 'OWASPZAP') return 'ZAP';
  if (s === 'WAPITI') return 'WAPITI';
  return null;
}

export function isScannerAvailableFromAgents(activeAgents, scannerKey) {
  const canonicalTarget = normalizeScannerKey(scannerKey);
  if (!canonicalTarget || !Array.isArray(activeAgents)) return false;

  const activeOnly = activeAgents.filter(a => a && (a.status === 'ACTIVE' || a.status === 'ONLINE'));
  for (const agent of activeOnly) {
    let caps = null;
    if (typeof agent.capabilities_json === 'string') {
      try {
        caps = JSON.parse(agent.capabilities_json || '{}');
      } catch {
        caps = null;
      }
    } else if (agent.capabilities_json) {
      caps = agent.capabilities_json;
    } else if (agent.capabilities) {
      caps = agent.capabilities;
    }

    if (!caps) continue;

    if (Array.isArray(caps)) {
      if (caps.some(c => normalizeScannerKey(c) === canonicalTarget)) {
        return true;
      }
    } else if (typeof caps === 'object') {
      for (const [k, v] of Object.entries(caps)) {
        if (normalizeScannerKey(k) === canonicalTarget) {
          if (v === true) return true;
          if (v && typeof v === 'object' && v.available === true) return true;
        }
      }
    }
  }

  return false;
}
