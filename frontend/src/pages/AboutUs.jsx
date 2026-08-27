import React, { useState } from 'react';
import {
  Sparkles, Layers, ShieldCheck, Database, Lock,
  ArrowRight, Activity, Terminal, GitMerge, Network, Shield, Clock
} from 'lucide-react';

const MODULES_DATA = [
  {
    id: 'M1',
    name: 'Multi-Scanner Ingestion Engine',
    short: 'Ingestion',
    icon: Database,
    color: '#3B82F6',
    bg: '#EFF6FF',
    desc: 'Normalizes disparate raw formats and schemas from multiple vulnerability scanners (OWASP ZAP, Nuclei, and OpenVAS) into a single, unified data payload.',
    input: 'SARIF logs, raw JSON schemas, scanner specific XML output.',
    output: 'Unified Vulnerability Telemetry Payload (v1.0 schema compliant).',
    tech: 'FastAPI validation, Pydantic data schemas, Schema mapping parsers.'
  },
  {
    id: 'M2',
    name: 'Cross-Scanner Deduplication',
    short: 'Deduplication',
    icon: GitMerge,
    color: '#8B5CF6',
    bg: '#F5F3FF',
    desc: 'Correlates raw findings matching endpoints, CVE-IDs, parameters, and AST hashes to ensure duplicates from different scanners do not cause ticket bloat.',
    input: 'Unified Vulnerability Telemetry Payload.',
    output: 'Unique Deduplicated Finding Records (with cross-reference scanner map).',
    tech: 'Vulnerability Signature Hashing, Parameter Collision Normalization.'
  },
  {
    id: 'M3',
    name: 'Confidence Corroboration Engine',
    short: 'Consensus',
    icon: ShieldCheck,
    color: '#0D9488',
    bg: '#F0FDFA',
    desc: 'Compares findings across scanner types to calculate an agreement score. If multiple scanners report the same issue, confidence dynamically scales to 96%+',
    input: 'Deduplicated Finding Records.',
    output: 'Confidence Index Score (0.0 - 1.0) and agreement tags.',
    tech: 'Multi-scanner Consensus Matrix, False-positive Probability Weighing.'
  },
  {
    id: 'M4',
    name: 'Threat Intelligence Enrichment',
    short: 'Threat Intel',
    icon: Network,
    color: '#F59E0B',
    bg: '#FFFBEB',
    desc: 'Enriches vulnerabilities with real-time exploitability feeds. Cross-checks CVEs directly against CISA KEV (Known Exploited) list and FIRST EPSS probability scores.',
    input: 'CVE-IDs from findings.',
    output: 'Exploitability Index (EPSS probability percent & CISA KEV flag).',
    tech: 'CISA KEV Catalog Cache, FIRST EPSS API sync pipelines.'
  },
  {
    id: 'M5',
    name: 'Dynamic Risk Scoring (0–100)',
    short: 'Risk Scoring',
    icon: Activity,
    color: '#EF4444',
    bg: '#FEF2FE',
    desc: 'Computes a mathematical severity score representing the true corporate risk by combining severity, confidence, exposure, and asset value.',
    input: 'CVSS, Confidence Index, EPSS, Asset criticality factor.',
    output: 'Dynamic Risk Index (0 - 100 severity index).',
    tech: 'Deterministic RizIntel Risk Formula: Risk = (CVSS × 0.25) + (EPSS × 25) + CISA KEV Bonus.'
  },
  {
    id: 'M6',
    name: 'Asset Context & Blast Radius',
    short: 'Asset Context',
    icon: Shield,
    color: '#6366F1',
    bg: '#EEF2FF',
    desc: 'Maps infrastructure details, PCI/PII data classifications, and network exposures (internal vs internet facing) to calculate actual operational blast radius.',
    input: 'Asset tags, network mapping, compliance tags.',
    output: 'Blast Radius Index (Low / Medium / High impact rating).',
    tech: 'Asset Landscape exposure scoring, PCI-DSS compliance constraint matrices.'
  },
  {
    id: 'M7',
    name: 'Remediation SLA Governance',
    short: 'SLA Engine',
    icon: Clock,
    color: '#EC4899',
    bg: '#FDF2F8',
    desc: 'Monitors real-time countdowns based on risk scores (e.g., 8-hour window for Critical findings) and schedules multi-tier alerts to Slack/PagerDuty before breach.',
    input: 'Dynamic Risk Index + SLA countdown rules.',
    output: 'Active SLA state, remaining countdown, Level-1/2 escalation triggers.',
    tech: 'Predictive Breach Forecast algorithms, PagerDuty & Slack webhooks.'
  },
  {
    id: 'M8',
    name: 'Human-in-the-Loop Audit Trail',
    short: 'HIL Audit',
    icon: Terminal,
    color: '#10B981',
    bg: '#F0FDF4',
    desc: 'Provides security analysts with override tools (accept priority, flag false positive) with mandatory rationale logging appended to an immutable ledger.',
    input: 'Analyst override command + decision justification.',
    output: 'Cryptographically signed audit trail logs (immutable).',
    tech: 'Security Override Ledger, Audit rationale hashes.'
  }
];

export default function AboutUs() {
  const [selectedModule, setSelectedModule] = useState(0);
  const currentModule = MODULES_DATA[selectedModule];
  const IconComponent = currentModule.icon;

  return (
    <div className="stack about-page-wrapper" style={{ gap: 16, width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
      {/* Compact Enterprise Hero */}
      <div className="page-hero" style={{ padding: '14px 20px', borderRadius: '12px' }}>
        <div className="hero-eyebrow" style={{ fontSize: 11, gap: 4 }}><Sparkles size={12} /> Platform Architecture</div>
        <h1 className="hero-title" style={{ fontSize: 24, marginBottom: 4, marginTop: 2 }}>
          About RizIntel & 8-Module Spec
        </h1>
        <p className="hero-subtitle" style={{ fontSize: 13, marginBottom: 0, lineHeight: 1.4 }}>
          An enterprise Continuous Threat Exposure Management (CTEM) architecture designed to solve vulnerability alert fatigue.
        </p>
      </div>

      {/* Main Introduction Card */}
      <div className="card" style={{ overflow: 'hidden', width: '100%', boxSizing: 'border-box' }}>
        <div className="card-body" style={{ padding: '16px 20px', position: 'relative' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <h4 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--color-primary)' }}>Engineered for Alert Fatigue Reduction</h4>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              Modern enterprises run multiple security scanners (DAST, SAST, Network, Cloud), generating thousands of unprioritized, noisy alerts.
              <strong> RizIntel</strong> unifies raw findings into actionable risk intelligence through a modular, deterministic 8-stage pipeline.
            </p>
          </div>
        </div>
      </div>

      {/* Interactive Pipeline Section */}
      <div className="card" style={{ width: '100%', boxSizing: 'border-box' }}>
        <div className="card-header" style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Layers size={16} color="var(--color-primary)" />
            <div className="card-title" style={{ fontSize: 15, fontWeight: 700 }}>Interactive Pipeline Explorer</div>
          </div>
        </div>
        <div className="card-body stack-4" style={{ padding: '14px 16px', width: '100%', boxSizing: 'border-box' }}>
          {/* Timeline Pipeline Stream (Overflow Safe) */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 4,
            overflowX: 'auto',
            padding: '10px 4px',
            borderBottom: '1px solid var(--border-color, #E2E8F0)',
            marginBottom: 14,
            width: '100%',
            boxSizing: 'border-box',
            scrollbarWidth: 'none'
          }}>
            {MODULES_DATA.map((mod, idx) => {
              const ModIcon = mod.icon;
              const isSelected = selectedModule === idx;
              return (
                <div key={mod.id} style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                  <button
                    type="button"
                    onClick={() => setSelectedModule(idx)}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: 5,
                      padding: '8px 10px',
                      borderRadius: '12px',
                      background: isSelected ? mod.bg : 'transparent',
                      border: isSelected ? `1.5px solid ${mod.color}` : '1.5px solid transparent',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      minWidth: '76px',
                    }}
                  >
                    <span style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: '36px',
                      height: '36px',
                      borderRadius: '50%',
                      background: isSelected ? mod.color : 'var(--border-color, #E2E8F0)',
                      color: isSelected ? '#FFFFFF' : 'var(--text-muted)',
                      transition: 'all 0.2s ease',
                      boxShadow: isSelected ? `0 2px 8px ${mod.color}40` : 'none'
                    }}>
                      <ModIcon size={17} />
                    </span>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: isSelected ? 700 : 600,
                      color: isSelected ? 'var(--text-primary)' : 'var(--text-muted)',
                      whiteSpace: 'nowrap'
                    }}>
                      {mod.id}: {mod.short}
                    </span>
                  </button>
                  {idx < MODULES_DATA.length - 1 && (
                    <ArrowRight size={13} style={{ color: 'var(--text-muted)', opacity: 0.45, flexShrink: 0 }} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Module Deep Details Card */}
          <div style={{
            display: 'flex',
            gap: 16,
            flexWrap: 'wrap',
            padding: 16,
            borderRadius: 10,
            background: 'var(--background-secondary, #F8FAFC)',
            border: `1.5px solid ${currentModule.color}25`,
            width: '100%',
            boxSizing: 'border-box'
          }}>
            {/* Visual Icon Box */}
            <div style={{
              width: 48,
              height: 48,
              borderRadius: 12,
              background: currentModule.bg,
              color: currentModule.color,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: `0 4px 12px ${currentModule.color}15`
            }}>
              <IconComponent size={22} />
            </div>

            {/* Spec Content */}
            <div style={{ flex: '1 1 260px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 10, boxSizing: 'border-box' }}>
              <div>
                <span style={{ fontSize: 10.5, fontWeight: 800, color: currentModule.color, textTransform: 'uppercase', letterSpacing: 0.5 }}>Module {currentModule.id} Spec</span>
                <h3 style={{ fontSize: 16, fontWeight: 700, margin: '1px 0 0' }}>{currentModule.name}</h3>
              </div>
              
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.45, margin: 0 }}>
                {currentModule.desc}
              </p>

              {/* Data Specifications Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginTop: 2, width: '100%', boxSizing: 'border-box' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: 0.5 }}>Telemetry Input</span>
                  <span style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500 }}>{currentModule.input}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: 0.5 }}>Engine Output</span>
                  <span style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500 }}>{currentModule.output}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: 0.5 }}>Algorithmic Core</span>
                  <span style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500, fontFamily: 'var(--font-mono)' }}>{currentModule.tech}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Grid overview of all engines */}
      <h2 style={{ fontSize: 15, fontWeight: 700, marginTop: 4, marginBottom: 0 }}>RizIntel Engine Catalog Overview</h2>
      <div className="grid-2" style={{ gap: 12, width: '100%', boxSizing: 'border-box' }}>
        {MODULES_DATA.map((mod) => {
          const ModIcon = mod.icon;
          return (
            <div key={mod.id} className="card" style={{ transition: 'transform 0.2s', cursor: 'pointer', minWidth: 0, width: '100%', boxSizing: 'border-box' }} onClick={() => {
              const idx = MODULES_DATA.findIndex(m => m.id === mod.id);
              setSelectedModule(idx);
              window.scrollTo({ top: 320, behavior: 'smooth' });
            }}>
              <div className="card-body" style={{ padding: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                  <span style={{
                    width: 28,
                    height: 28,
                    borderRadius: 7,
                    background: mod.bg,
                    color: mod.color,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 'bold',
                    fontSize: 12,
                    flexShrink: 0
                  }}>
                    <ModIcon size={14} />
                  </span>
                  <h3 style={{ fontSize: 13.5, fontWeight: 700, margin: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{mod.id}: {mod.name}</h3>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4, margin: 0 }}>
                  {mod.desc}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Compliance Information */}
      <div className="card" style={{ marginTop: 4, width: '100%', boxSizing: 'border-box' }}>
        <div className="card-body" style={{ padding: '14px 18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <h4 style={{ fontSize: 13.5, fontWeight: 700, margin: 0 }}>Security Audited Architecture</h4>
              <p style={{ fontSize: 11.5, color: 'var(--text-secondary)', margin: '2px 0 0' }}>All 8 pipelines are ISO-certified and compliant with SOC-2 policies.</p>
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11.5, padding: '4px 10px', border: '1px solid var(--border-color, #E2E8F0)', borderRadius: 6, display: 'inline-flex', alignItems: 'center', gap: 5, fontWeight: 600 }}>
                <ShieldCheck size={13} color="#7C3AED" /> SOC 2 Type II
              </span>
              <span style={{ fontSize: 11.5, padding: '4px 10px', border: '1px solid var(--border-color, #E2E8F0)', borderRadius: 6, display: 'inline-flex', alignItems: 'center', gap: 5, fontWeight: 600 }}>
                <Lock size={13} color="#7C3AED" /> ISO 27001
              </span>
              <span style={{ fontSize: 11.5, padding: '4px 10px', border: '1px solid var(--border-color, #E2E8F0)', borderRadius: 6, display: 'inline-flex', alignItems: 'center', gap: 5, fontWeight: 600 }}>
                <Database size={13} color="#7C3AED" /> CISA KEV Sync
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
