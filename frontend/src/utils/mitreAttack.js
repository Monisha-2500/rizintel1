/**
 * mitreAttack.js — M8 Contextual MITRE ATT&CK Enrichment for RizIntel
 *
 * PURPOSE:
 * ─────────────────────────────────────────────────────────────
 * Provides lightweight, evidence-based ATT&CK framework mapping for findings.
 * Mappings are CONTEXTUAL / INFERRED — they describe plausible adversary
 * techniques consistent with the finding's vulnerability class. They are NOT
 * proof of an observed attack or a direct detection event.
 *
 * This module is independent (M8 enrichment):
 *   – Does NOT modify M5 risk scores
 *   – Does NOT restructure existing finding data
 *   – Exports a single pure function: getMitreAttackContext(finding)
 *
 * Returns an object with:
 *   isMapped        : boolean  — whether a mapping was found
 *   technique_id    : string   — e.g. "T1190"
 *   technique_name  : string   — e.g. "Exploit Public-Facing Application"
 *   tactic          : string   — e.g. "Initial Access"
 *   tactic_id       : string   — e.g. "TA0001"
 *   sub_technique   : string   — e.g. "SQL Injection" (optional)
 *   sub_technique_id: string   — e.g. "T1190.001" (optional)
 *   confidence      : string   — "HIGH" | "MEDIUM" | "LOW"
 *   rationale       : string   — concise human-readable reason for the mapping
 *   source          : string   — mapping basis: "CVE Class", "Vuln Pattern", etc.
 *   mitre_url       : string   — link to the MITRE ATT&CK technique page
 * ─────────────────────────────────────────────────────────────
 */

/** NOT_MAPPED — returned when no confident mapping is possible. */
export const NOT_MAPPED = {
  isMapped: false,
  technique_id: null,
  technique_name: null,
  tactic: null,
  tactic_id: null,
  sub_technique: null,
  sub_technique_id: null,
  confidence: null,
  rationale: 'No confident MITRE ATT&CK mapping identified for this vulnerability type.',
  source: null,
  mitre_url: null,
};

/** Technique catalog — structured by vulnerability keyword patterns. */
export const TECHNIQUE_CATALOG = [
  {
    keywords: ['sql injection', 'sqli', 'sql', 'database injection', 'unparameterized', 'unsanitized query'],
    technique_id: 'T1190',
    technique_name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    tactic_id: 'TA0001',
    sub_technique: 'SQL Injection',
    sub_technique_id: 'T1190.001',
    confidence: 'HIGH',
    rationale: 'SQL Injection exploits vulnerable input handling in public-facing applications to gain unauthorized data access or execute commands.',
    source: 'CVE Class + Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1190/',
  },
  {
    keywords: ['cross-site scripting', 'xss', 'reflected xss', 'stored xss', 'dom xss'],
    technique_id: 'T1189',
    technique_name: 'Drive-by Compromise',
    tactic: 'Initial Access',
    tactic_id: 'TA0001',
    sub_technique: 'XSS-Facilitated Code Execution',
    sub_technique_id: null,
    confidence: 'MEDIUM',
    rationale: 'XSS flaws can be chained to execute attacker-controlled scripts in victim browsers, facilitating initial compromise vectors mapped to T1189.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1189/',
  },
  {
    keywords: ['remote code execution', 'rce', 'code execution', 'command injection', 'os command injection'],
    technique_id: 'T1059',
    technique_name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    tactic_id: 'TA0002',
    sub_technique: 'Unix Shell / OS Command Injection',
    sub_technique_id: 'T1059.004',
    confidence: 'HIGH',
    rationale: 'RCE and command injection vulnerabilities allow adversaries to execute arbitrary OS commands, consistent with T1059.',
    source: 'CVE Class + Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1059/',
  },
  {
    keywords: ['path traversal', 'directory traversal', 'local file inclusion', 'lfi', 'file inclusion'],
    technique_id: 'T1083',
    technique_name: 'File and Directory Discovery',
    tactic: 'Discovery',
    tactic_id: 'TA0007',
    sub_technique: null,
    sub_technique_id: null,
    confidence: 'MEDIUM',
    rationale: 'Path traversal enables adversaries to enumerate and access files outside the intended scope, matching T1083 discovery techniques.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1083/',
  },
  {
    keywords: ['authentication bypass', 'broken authentication', 'auth bypass', 'session fixation', 'missing auth'],
    technique_id: 'T1078',
    technique_name: 'Valid Accounts',
    tactic: 'Privilege Escalation',
    tactic_id: 'TA0004',
    sub_technique: 'Authentication Bypass',
    sub_technique_id: null,
    confidence: 'MEDIUM',
    rationale: 'Authentication bypass flaws allow adversaries to leverage valid account privileges without credentials, aligned with T1078.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1078/',
  },
  {
    keywords: ['server-side request forgery', 'ssrf'],
    technique_id: 'T1090',
    technique_name: 'Proxy',
    tactic: 'Command and Control',
    tactic_id: 'TA0011',
    sub_technique: 'Internal Proxy via SSRF',
    sub_technique_id: null,
    confidence: 'MEDIUM',
    rationale: 'SSRF allows attackers to route requests through the server to reach internal resources, consistent with proxy and internal recon behaviors.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1090/',
  },
  {
    keywords: ['insecure deserialization', 'deserialization', 'object injection', 'java deserialization'],
    technique_id: 'T1059',
    technique_name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    tactic_id: 'TA0002',
    sub_technique: 'Deserialization-Based Code Execution',
    sub_technique_id: null,
    confidence: 'HIGH',
    rationale: 'Insecure deserialization enables attackers to execute arbitrary code through crafted serialized objects, aligning with T1059.',
    source: 'CVE Class',
    mitre_url: 'https://attack.mitre.org/techniques/T1059/',
  },
  {
    keywords: ['xml external entity', 'xxe', 'external entity injection'],
    technique_id: 'T1005',
    technique_name: 'Data from Local System',
    tactic: 'Collection',
    tactic_id: 'TA0009',
    sub_technique: 'XXE-Based File Disclosure',
    sub_technique_id: null,
    confidence: 'HIGH',
    rationale: 'XXE vulnerabilities allow extraction of local file content and internal network information via malicious XML, consistent with T1005.',
    source: 'CVE Class',
    mitre_url: 'https://attack.mitre.org/techniques/T1005/',
  },
  {
    keywords: ['improper access control', 'broken access control', 'privilege escalation', 'idor', 'insecure direct object'],
    technique_id: 'T1548',
    technique_name: 'Abuse Elevation Control Mechanism',
    tactic: 'Privilege Escalation',
    tactic_id: 'TA0004',
    sub_technique: 'Broken Access Control',
    sub_technique_id: null,
    confidence: 'MEDIUM',
    rationale: 'Broken access control allows unauthorized actors to elevate their access beyond authorization level, matching T1548.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1548/',
  },
  {
    keywords: ['hardcoded credential', 'default credential', 'exposed secret', 'exposed api key', 'secret in code', 'leaked credential'],
    technique_id: 'T1552',
    technique_name: 'Unsecured Credentials',
    tactic: 'Credential Access',
    tactic_id: 'TA0006',
    sub_technique: 'Credentials In Files',
    sub_technique_id: 'T1552.001',
    confidence: 'HIGH',
    rationale: 'Hardcoded or exposed credentials in code or configuration files are a primary credential theft technique, matching T1552.001.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1552/',
  },
  {
    keywords: ['open redirect', 'url redirection', 'unvalidated redirect'],
    technique_id: 'T1566',
    technique_name: 'Phishing',
    tactic: 'Initial Access',
    tactic_id: 'TA0001',
    sub_technique: 'Spearphishing via Link (Redirect)',
    sub_technique_id: 'T1566.002',
    confidence: 'LOW',
    rationale: 'Open redirects can be weaponized in phishing campaigns to obscure malicious destinations behind trusted domains, loosely mapping to T1566.002.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1566/',
  },
  {
    keywords: ['cross-site request forgery', 'csrf'],
    technique_id: 'T1185',
    technique_name: 'Browser Session Hijacking',
    tactic: 'Collection',
    tactic_id: 'TA0009',
    sub_technique: null,
    sub_technique_id: null,
    confidence: 'MEDIUM',
    rationale: 'CSRF exploits authenticated browser sessions to perform unauthorized actions on behalf of the victim, aligned with T1185.',
    source: 'Vulnerability Pattern',
    mitre_url: 'https://attack.mitre.org/techniques/T1185/',
  },
];

/**
 * getMitreAttackContext — returns contextual ATT&CK mapping for a finding.
 *
 * Matching priority:
 *   1. finding.vulnerability_type  (most specific)
 *   2. finding.title
 *   3. finding.detail.scanner_consensus.vulnerability_type
 *   4. finding.detail.explanation.summary
 *   5. finding.detail.explanation.root_cause
 *
 * @param {Object} finding — RizIntel finding object
 * @returns {Object}       — Mapping result (see module header for fields)
 */
export function getMitreAttackContext(finding) {
  if (!finding || typeof finding !== 'object') return NOT_MAPPED;

  const searchableSources = [
    finding.vulnerability_type,
    finding.title,
    finding.detail?.scanner_consensus?.vulnerability_type,
    finding.detail?.explanation?.summary,
    finding.detail?.explanation?.root_cause,
  ]
    .filter(s => typeof s === 'string' && s.trim().length > 0)
    .map(s => s.toLowerCase());

  if (searchableSources.length === 0) return NOT_MAPPED;

  for (const technique of TECHNIQUE_CATALOG) {
    for (const source of searchableSources) {
      const matched = technique.keywords.some(kw => source.includes(kw));
      if (matched) {
        return {
          isMapped: true,
          technique_id: technique.technique_id,
          technique_name: technique.technique_name,
          tactic: technique.tactic,
          tactic_id: technique.tactic_id,
          sub_technique: technique.sub_technique,
          sub_technique_id: technique.sub_technique_id,
          confidence: technique.confidence,
          rationale: technique.rationale,
          source: technique.source,
          mitre_url: technique.mitre_url,
        };
      }
    }
  }

  return NOT_MAPPED;
}

