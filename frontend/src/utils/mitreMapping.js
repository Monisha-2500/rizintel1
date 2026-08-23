/**
 * mitreMapping.js — MITRE ATT&CK Contextual & Inferred Mapping Engine for RizIntel
 *
 * GOVERNANCE NOTICE:
 * ─────────────────────────────────────────────────────────────
 * All mappings produced by this module are strictly contextual and
 * inferred based on vulnerability classification and threat intelligence.
 * They represent theoretical attacker exploitation vectors and do NOT
 * constitute empirical telemetry or proof of observed attacker activity.
 * ─────────────────────────────────────────────────────────────
 */

export const MITRE_ATTACK_DATABASE = {
  SQL_INJECTION: {
    mapped: true,
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    subTechniqueId: 'T1059',
    subTechniqueName: 'Command and Scripting Interpreter',
    confidence: 'HIGH',
    confidenceScore: 95,
    rationale: 'Adversaries may exploit SQL injection vulnerabilities in web-facing endpoints to bypass authentication, execute unauthorized database queries, or pivot to command execution.',
    url: 'https://attack.mitre.org/techniques/T1190/',
    inferredStage: 'Weaponization & Initial Access',
  },
  RCE: {
    mapped: true,
    tacticId: 'TA0002',
    tacticName: 'Execution',
    techniqueId: 'T1203',
    techniqueName: 'Exploitation for Client/Server Execution',
    subTechniqueId: 'T1059.004',
    subTechniqueName: 'Unix Shell Execution',
    confidence: 'HIGH',
    confidenceScore: 98,
    rationale: 'Remote Code Execution (RCE) flaws allow adversaries to execute arbitrary system-level payloads, spawn interactive shells, and establish footholds on targeted hosts.',
    url: 'https://attack.mitre.org/techniques/T1203/',
    inferredStage: 'Execution & Host Compromise',
  },
  XSS: {
    mapped: true,
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    techniqueId: 'T1189',
    techniqueName: 'Drive-by Compromise',
    subTechniqueId: 'T1059.007',
    subTechniqueName: 'JavaScript Execution',
    confidence: 'MEDIUM',
    confidenceScore: 80,
    rationale: 'Cross-Site Scripting permits adversaries to execute malicious JavaScript in victims\' browsers to hijack session tokens, capture keystrokes, or redirect users to phishing portals.',
    url: 'https://attack.mitre.org/techniques/T1189/',
    inferredStage: 'Credential Harvesting & Session Hijacking',
  },
  AUTH_BYPASS: {
    mapped: true,
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    techniqueId: 'T1556',
    techniqueName: 'Modify Authentication Process',
    subTechniqueId: 'T1078',
    subTechniqueName: 'Valid Accounts',
    confidence: 'HIGH',
    confidenceScore: 92,
    rationale: 'Authentication bypass vulnerabilities enable untrusted actors to circumvent access verification mechanisms and obtain unauthorized access without valid credentials.',
    url: 'https://attack.mitre.org/techniques/T1556/',
    inferredStage: 'Privilege Escalation & Unauthorized Access',
  },
  SSRF: {
    mapped: true,
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    subTechniqueId: 'T1090',
    subTechniqueName: 'Proxy',
    confidence: 'HIGH',
    confidenceScore: 90,
    rationale: 'Server-Side Request Forgery allows adversaries to force internal web servers to initiate unauthorized network connections to internal services or cloud metadata endpoints (e.g. AWS IMDS).',
    url: 'https://attack.mitre.org/techniques/T1190/',
    inferredStage: 'Internal Discovery & Lateral Movement',
  },
  DATA_EXPOSURE: {
    mapped: true,
    tacticId: 'TA0009',
    tacticName: 'Collection',
    techniqueId: 'T1005',
    techniqueName: 'Data from Local System',
    subTechniqueId: 'T1530',
    subTechniqueName: 'Data from Cloud Storage',
    confidence: 'MEDIUM',
    confidenceScore: 85,
    rationale: 'Sensitive data exposure allows attackers to harvest unencrypted credentials, PII, or financial records directly from misconfigured endpoints.',
    url: 'https://attack.mitre.org/techniques/T1005/',
    inferredStage: 'Data Collection & Exfiltration',
  },
  ACCESS_CONTROL: {
    mapped: true,
    tacticId: 'TA0004',
    tacticName: 'Privilege Escalation',
    techniqueId: 'T1068',
    techniqueName: 'Exploitation for Privilege Escalation',
    subTechniqueId: 'T1548',
    subTechniqueName: 'Abuse Elevation Control Mechanism',
    confidence: 'MEDIUM',
    confidenceScore: 80,
    rationale: 'Broken access control permits unauthorized users to access restricted administrative resources, modify configurations, or view other tenants\' assets.',
    url: 'https://attack.mitre.org/techniques/T1068/',
    inferredStage: 'Privilege Escalation',
  },
  VULNERABLE_COMPONENT: {
    mapped: true,
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    techniqueId: 'T1195',
    techniqueName: 'Supply Chain Compromise',
    subTechniqueId: 'T1190',
    subTechniqueName: 'Exploit Public-Facing Application',
    confidence: 'MEDIUM',
    confidenceScore: 75,
    rationale: 'Outdated or unpatched software dependencies often harbor publicly known vulnerabilities that adversaries scan for and exploit during automated campaigns.',
    url: 'https://attack.mitre.org/techniques/T1195/',
    inferredStage: 'Initial Foothold',
  },
  INFO_DISCLOSURE: {
    mapped: true,
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    techniqueId: 'T1592',
    techniqueName: 'Gather Victim Host Information',
    subTechniqueId: 'T1592.002',
    subTechniqueName: 'Software Configuration',
    confidence: 'LOW',
    confidenceScore: 65,
    rationale: 'Informational disclosures (such as version banners or stack traces) assist adversaries in tailoring targeted exploits against specific platform versions.',
    url: 'https://attack.mitre.org/techniques/T1592/',
    inferredStage: 'Pre-Attack Reconnaissance',
  },
  SECURITY_HEADER: {
    mapped: false,
    tacticId: null,
    tacticName: null,
    techniqueId: null,
    techniqueName: null,
    confidence: 'NOT_MAPPED',
    confidenceScore: 0,
    rationale: 'Missing defensive security headers (e.g. CSP, HSTS) represent defensive gaps rather than direct adversary techniques. No 1:1 ATT&CK technique mapping.',
    url: null,
    inferredStage: 'N/A',
  },
};

/**
 * getMitreAttackMapping — returns contextual ATT&CK mapping for a given finding.
 * Gracefully handles unmapped or unknown vulnerability types.
 */
export function getMitreAttackMapping(finding) {
  if (!finding) return null;

  const rawType = (finding.vulnerability_type || '').toUpperCase().trim();
  const name = (finding.vulnerability_name || '').toUpperCase().trim();

  let mapping = MITRE_ATTACK_DATABASE[rawType];

  if (!mapping) {
    // Fallback matching by name keyword
    if (name.includes('SQL')) mapping = MITRE_ATTACK_DATABASE.SQL_INJECTION;
    else if (name.includes('RCE') || name.includes('COMMAND') || name.includes('EXECUTION')) mapping = MITRE_ATTACK_DATABASE.RCE;
    else if (name.includes('XSS') || name.includes('SCRIPT')) mapping = MITRE_ATTACK_DATABASE.XSS;
    else if (name.includes('AUTH') || name.includes('LOGIN')) mapping = MITRE_ATTACK_DATABASE.AUTH_BYPASS;
    else if (name.includes('SSRF')) mapping = MITRE_ATTACK_DATABASE.SSRF;
    else if (name.includes('HEADER')) mapping = MITRE_ATTACK_DATABASE.SECURITY_HEADER;
    else if (name.includes('DISCLOSURE') || name.includes('INFO')) mapping = MITRE_ATTACK_DATABASE.INFO_DISCLOSURE;
    else if (name.includes('COMPONENT') || name.includes('OUTDATED')) mapping = MITRE_ATTACK_DATABASE.VULNERABLE_COMPONENT;
    else if (name.includes('ACCESS') || name.includes('PERMISSION')) mapping = MITRE_ATTACK_DATABASE.ACCESS_CONTROL;
  }

  if (!mapping || !mapping.mapped) {
    return {
      mapped: false,
      statusLabel: 'Not mapped',
      tacticId: 'N/A',
      tacticName: 'Not Mapped',
      techniqueId: 'N/A',
      techniqueName: 'Not Mapped',
      confidence: 'NOT_MAPPED',
      confidenceScore: 0,
      rationale: mapping?.rationale || 'No standardized MITRE ATT&CK technique mapping established for this specific vulnerability pattern.',
      url: null,
      inferredStage: 'N/A',
      isContextual: true,
    };
  }

  return {
    ...mapping,
    statusLabel: `${mapping.techniqueId}: ${mapping.techniqueName}`,
    isContextual: true,
  };
}
