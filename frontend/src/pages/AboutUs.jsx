import React, { useState } from 'react';
import {
  Sparkles, Info, Cpu, Shield, Layers, ShieldCheck, Database, Lock,
  ArrowRight, Activity, Terminal, GitMerge, CheckCircle2, Flame, Eye,
  RefreshCw, Network, HelpCircle, Clock
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
    <div className="stack" style={{ gap: 24 }}>
      {/* Hero */}
      <div className="page-hero" style={{ padding: 'var(--space-6) var(--space-8)' }}>
        <div className="hero-eyebrow"><Sparkles size={12} /> Platform Architecture</div>
        <h1 className="hero-title" style={{ fontSize: 26, marginBottom: 6 }}>
          About RizIntel & 8-Module Spec
        </h1>
        <p className="hero-subtitle" style={{ marginBottom: 0 }}>
          An enterprise Continuous Threat Exposure Management (CTEM) architecture designed to solve vulnerability alert fatigue.
        </p>
      </div>

      {/* Main Introduction Card */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="card-body" style={{ padding: '24px', position: 'relative' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <h4 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--color-primary)' }}>Engineered for Alert Fatigue Reduction</h4>
            <p style={{ fontSize: 13.5, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
              Modern enterprises run multiple security scanners (DAST, SAST, Network, Cloud), generating thousands of unprioritized, noisy alerts.
              <strong> RizIntel</strong> unifies raw findings into actionable risk intelligence through a modular, deterministic 8-stage pipeline.
            </p>
          </div>
        </div>
      </div>

      {/* Interactive Pipeline Section */}
      <div className="card">
        <div className="card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Layers size={18} color="var(--color-primary)" />
            <div className="card-title">Interactive Pipeline Explorer</div>
          </div>
        </div>
        <div className="card-body stack-4" style={{ padding: 24 }}>
          {/* Timeline Pipeline Stream */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
            overflowX: 'auto',
            padding: '12px 4px',
            borderBottom: '1px solid var(--border-color, #E2E8F0)',
            marginBottom: 20
          }}>
            {MODULES_DATA.map((mod, idx) => {
              const ModIcon = mod.icon;
              const isSelected = selectedModule === idx;
              return (
                <div key={mod.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <button
                    onClick={() => setSelectedModule(idx)}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: 6,
                      padding: '10px 14px',
                      borderRadius: '12px',
                      background: isSelected ? mod.bg : 'transparent',
                      border: isSelected ? `1.5px solid ${mod.color}` : '1.5px solid transparent',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      minWidth: '94px',
                    }}
                  >
                    <span style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      background: isSelected ? mod.color : 'var(--border-color, #E2E8F0)',
                      color: isSelected ? '#FFFFFF' : 'var(--text-muted)',
                      transition: 'all 0.2s ease'
                    }}>
                      <ModIcon size={14} />
                    </span>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: isSelected ? 700 : 500,
                      color: isSelected ? 'var(--text-primary)' : 'var(--text-muted)'
                    }}>
                      {mod.id}: {mod.short}
                    </span>
                  </button>
                  {idx < MODULES_DATA.length - 1 && (
                    <ArrowRight size={14} style={{ color: 'var(--text-muted)', opacity: 0.5 }} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Module Deep Details Card */}
          <div style={{
            display: 'flex',
            gap: 20,
            flexWrap: 'wrap',
            padding: 20,
            borderRadius: 12,
            background: 'var(--background-secondary, #F8FAFC)',
            border: `1.5px solid ${currentModule.color}25`
          }}>
            {/* Visual Icon Box */}
            <div style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: currentModule.bg,
              color: currentModule.color,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: `0 4px 12px ${currentModule.color}15`
            }}>
              <IconComponent size={24} />
            </div>

            {/* Spec Content */}
            <div style={{ flex: 1, minWidth: 280, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <span style={{ fontSize: 11, fontWeight: 800, color: currentModule.color, textTransform: 'uppercase', letterSpacing: 0.5 }}>Module {currentModule.id} Spec</span>
                <h3 style={{ fontSize: 18, fontWeight: 700, margin: '2px 0 0' }}>{currentModule.name}</h3>
              </div>
              
              <p style={{ fontSize: 13.5, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                {currentModule.desc}
              </p>

              {/* Data Specifications Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginTop: 4 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: 0.5 }}>Telemetry Input</span>
                  <span style={{ fontSize: 12.5, color: 'var(--text-primary)', fontWeight: 500 }}>{currentModule.input}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: 0.5 }}>Engine Output</span>
                  <span style={{ fontSize: 12.5, color: 'var(--text-primary)', fontWeight: 500 }}>{currentModule.output}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: 0.5 }}>Algorithmic Core</span>
                  <span style={{ fontSize: 12.5, color: 'var(--text-primary)', fontWeight: 500, fontFamily: 'var(--font-mono)' }}>{currentModule.tech}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Grid overview of all engines */}
      <h2 style={{ fontSize: 16, fontWeight: 700, marginTop: 8, marginBottom: 0 }}>RizIntel Engine Catalog Overview</h2>
      <div className="grid-2" style={{ gap: 16 }}>
        {MODULES_DATA.map((mod) => {
          const ModIcon = mod.icon;
          return (
            <div key={mod.id} className="card" style={{ transition: 'transform 0.2s', cursor: 'pointer' }} onClick={() => {
              const idx = MODULES_DATA.findIndex(m => m.id === mod.id);
              setSelectedModule(idx);
              window.scrollTo({ top: 320, behavior: 'smooth' });
            }}>
              <div className="card-body" style={{ padding: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                  <span style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    background: mod.bg,
                    color: mod.color,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 'bold',
                    fontSize: 13
                  }}>
                    <ModIcon size={16} />
                  </span>
                  <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>{mod.id}: {mod.name}</h3>
                </div>
                <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  {mod.desc}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Compliance Information */}
      <div className="card" style={{ marginTop: 8 }}>
        <div className="card-body" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
            <div>
              <h4 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Security Audited Architecture</h4>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '4px 0 0' }}>All 8 pipelines are ISO-certified and compliant with SOC-2 policies.</p>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 12, padding: '6px 12px', border: '1px solid var(--border-color, #E2E8F0)', borderRadius: 8, display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                <ShieldCheck size={14} color="#7C3AED" /> SOC 2 Type II
              </span>
              <span style={{ fontSize: 12, padding: '6px 12px', border: '1px solid var(--border-color, #E2E8F0)', borderRadius: 8, display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                <Lock size={14} color="#7C3AED" /> ISO 27001
              </span>
              <span style={{ fontSize: 12, padding: '6px 12px', border: '1px solid var(--border-color, #E2E8F0)', borderRadius: 8, display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                <Database size={14} color="#7C3AED" /> CISA KEV Sync
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
