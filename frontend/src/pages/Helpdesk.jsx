import React, { useState, useMemo } from 'react';
import {
  HelpCircle, MessageSquare, BookOpen, ChevronRight, CheckCircle2,
  Shield, Clock, Search, Info, Lock, ArrowRight, LifeBuoy
} from 'lucide-react';

const FAQS = [
  {
    q: 'How does Risk Scoring calculate final severity (0–100)?',
    a: 'RizIntel calculates risk using a deterministic scoring model that combines vulnerability severity, exploit probability, known exploitation, asset criticality, internet exposure, and scanner consensus: Risk = (CVSS Base × 0.25) + (EPSS Probability × 25) + (CISA KEV Bonus: 15 pts) + (Asset Criticality Factor × 15) + (Internet Exposure: 10 pts) + (Scanner Consensus: 10 pts). Scores ≥90 trigger Critical severity and strict 8h SLA remediation windows.'
  },
  {
    q: 'How does Intelligent Deduplication correlate findings across scanners?',
    a: 'Intelligent Deduplication correlates raw telemetry from ZAP, Nuclei, and OpenVAS using target endpoint normalization, CVE-ID cross-matching, parameter collision analysis, and AST vulnerability signature hashing to eliminate redundant duplicate tickets.'
  },
  {
    q: 'What triggers automated SLA breach escalations?',
    a: 'SLA & Remediation Automation actively monitors real-time countdown timers. If a Critical finding reaches 75% of its 8-hour remediation window without an analyst in-progress assignment, it triggers an automated Level-1 Slack/PagerDuty escalation to the SOC Lead.'
  },
  {
    q: 'How do analyst review and audit overrides work?',
    a: 'Security analysts can override algorithmic priority (Accept Priority, Escalate, Downgrade, Mark False Positive). Every decision requires a mandatory rationale and is cryptographically appended to an immutable audit trail for decision history and provenance.'
  }
];

export default function Helpdesk() {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFaq, setExpandedFaq] = useState(0);
  const [contactForm, setContactForm] = useState({
    name: '',
    email: '',
    inquiryType: 'Technical Support',
    priority: 'High',
    message: ''
  });
  const [contactSubmitted, setContactSubmitted] = useState(false);
  const [submittingContact, setSubmittingContact] = useState(false);

  const handleContactSubmit = (e) => {
    e.preventDefault();
    if (!contactForm.name.trim() || !contactForm.email.trim() || !contactForm.message.trim()) return;
    setSubmittingContact(true);
    setTimeout(() => {
      setSubmittingContact(false);
      setContactSubmitted(true);
      setTimeout(() => {
        setContactSubmitted(false);
        setContactForm({ name: '', email: '', inquiryType: 'Technical Support', priority: 'High', message: '' });
      }, 5000);
    }, 800);
  };

  const filteredFaqs = useMemo(() => {
    if (!searchQuery.trim()) return FAQS;
    return FAQS.filter(
      faq =>
        faq.q.toLowerCase().includes(searchQuery.toLowerCase()) ||
        faq.a.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [searchQuery]);

  return (
    <div className="stack helpdesk-page-wrapper" style={{ gap: 16, width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
      {/* Hero Header */}
      <div className="page-hero" style={{ padding: '14px 20px', borderRadius: '12px' }}>
        <div className="hero-eyebrow" style={{ fontSize: 11, gap: 4 }}><HelpCircle size={12} /> Help Desk & Support</div>
        <h1 className="hero-title" style={{ fontSize: 24, marginBottom: 4, marginTop: 2 }}>
          SOC Support Portal & Knowledge Base
        </h1>
        <p className="hero-subtitle" style={{ fontSize: 13, marginBottom: 0, lineHeight: 1.4 }}>
          Find answers to common questions about risk metrics, scanner consensus, and SLAs, or submit a SOC support ticket.
        </p>
      </div>

      {/* Metrics Summary Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, width: '100%', boxSizing: 'border-box' }}>
        <div className="card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--color-primary, #7C3AED)', minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ background: '#EEF2FF', padding: 7, borderRadius: 8, color: '#4F46E5', display: 'flex', flexShrink: 0 }}>
              <BookOpen size={16} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Knowledge Base</div>
              <div style={{ fontSize: 13.5, fontWeight: 700, marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>Core Security Intelligence</div>
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--color-purple, #9333EA)', minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ background: '#F5F3FF', padding: 7, borderRadius: 8, color: '#7C3AED', display: 'flex', flexShrink: 0 }}>
              <Clock size={16} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Response Standard</div>
              <div style={{ fontSize: 13.5, fontWeight: 700, marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>SOC SLA &lt; 5m Dispatch</div>
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--color-teal-dk, #0D9488)', minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ background: '#F0FDFA', padding: 7, borderRadius: 8, color: '#0D9488', display: 'flex', flexShrink: 0 }}>
              <Lock size={16} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Security Level</div>
              <div style={{ fontSize: 13.5, fontWeight: 700, marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>TLS 1.3 Cryptographic Audit</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid (2 Columns, Overflow-Safe) */}
      <div className="grid-2 helpdesk-main-grid" style={{ alignItems: 'start', gap: 16, width: '100%', boxSizing: 'border-box' }}>
        {/* Left Column: FAQ Accordion */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', minWidth: 0, width: '100%', boxSizing: 'border-box' }}>
          <div className="card-header" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <LifeBuoy size={16} color="var(--color-primary, #7C3AED)" />
              <div className="card-title" style={{ fontSize: 15, fontWeight: 700 }}>Interactive FAQ Search</div>
            </div>
            {/* FAQ Search Field */}
            <div style={{ position: 'relative', width: '190px', maxWidth: '100%' }}>
              <input
                type="text"
                placeholder="Search queries..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '5px 10px 5px 30px',
                  borderRadius: '14px',
                  border: '1px solid var(--border-color, #E2E8F0)',
                  fontSize: '12px',
                  background: 'transparent',
                  boxSizing: 'border-box',
                }}
              />
              <Search size={12} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            </div>
          </div>
          <div className="card-body stack-3" style={{ padding: '12px 16px' }}>
            <div className="faq-accordion-list">
              {filteredFaqs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px 16px', color: 'var(--text-muted)' }}>
                  <Search size={22} style={{ marginBottom: 6, opacity: 0.5 }} />
                  <div style={{ fontSize: 13 }}>No FAQ matching "{searchQuery}"</div>
                </div>
              ) : (
                filteredFaqs.map((item, idx) => (
                  <div 
                    key={idx} 
                    className={`faq-card ${expandedFaq === idx ? 'expanded' : ''}`} 
                    style={{ 
                      marginBottom: '8px', 
                      borderRadius: '8px', 
                      border: expandedFaq === idx ? '1px solid rgba(124, 58, 237, 0.3)' : '1px solid var(--border-color, #E2E8F0)',
                      transition: 'all 0.2s ease',
                      overflow: 'hidden'
                    }}
                  >
                    <div 
                      className="faq-q-row" 
                      onClick={() => setExpandedFaq(expandedFaq === idx ? -1 : idx)} 
                      style={{ 
                        cursor: 'pointer', 
                        padding: '10px 14px', 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'center',
                        gap: 8,
                        background: expandedFaq === idx ? 'rgba(124, 58, 237, 0.03)' : 'transparent'
                      }}
                    >
                      <span className="faq-q-text" style={{ fontWeight: 600, fontSize: '13px', lineHeight: 1.35 }}>{item.q}</span>
                      <ChevronRight size={15} className="faq-arrow" style={{ transition: 'transform 0.2s', transform: expandedFaq === idx ? 'rotate(90deg)' : 'none', color: 'var(--color-primary, #7C3AED)', flexShrink: 0 }} />
                    </div>
                    {expandedFaq === idx && (
                      <div className="faq-a-body" style={{ padding: '4px 14px 10px', fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                        <p style={{ margin: 0 }}>{item.a}</p>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Explanatory Info Strip */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '8px 12px', borderRadius: 8, background: '#F8FAFC', border: '1px solid #E2E8F0', marginTop: 8 }}>
              <Info size={13} color="#7C3AED" style={{ marginTop: 2, flexShrink: 0 }} />
              <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.45 }}>
                Metrics are automatically compiled from active SLA instances and system pipeline health logs. Overrides require security signature credentials.
              </p>
            </div>
          </div>
        </div>

        {/* Right Column: Contact SOC Operations Form */}
        <div className="card" style={{ minWidth: 0, width: '100%', boxSizing: 'border-box' }}>
          <div className="card-header" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
            <MessageSquare size={16} color="var(--color-purple, #9333EA)" />
            <div className="card-title" style={{ fontSize: 15, fontWeight: 700 }}>SOC Dispatch Incident System</div>
          </div>
          <div className="card-body" style={{ padding: '12px 16px' }}>
            {contactSubmitted ? (
              <div className="contact-success-box" style={{ textAlign: 'center', padding: '24px 16px' }}>
                <div className="cs-icon" style={{ marginBottom: 12 }}><CheckCircle2 size={40} color="#10B981" /></div>
                <h3 style={{ fontSize: 16, marginBottom: 6, fontWeight: 700 }}>Ticket Dispatched Successfully!</h3>
                <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.45, margin: 0 }}>
                  Your incident log is registered as ticket <strong>#INC-{Math.floor(100000 + Math.random() * 900000)}</strong> and forwarded to Security Engineers.
                </p>
              </div>
            ) : (
              <form className="contact-form-grid" onSubmit={handleContactSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 10, width: '100%', boxSizing: 'border-box' }}>
                {/* 2-Column Row for Name & Email */}
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10, width: '100%', boxSizing: 'border-box' }}>
                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
                    <label style={{ fontSize: 11.5, fontWeight: 600, color: '#334155' }}>Your Name *</label>
                    <input
                      type="text"
                      placeholder="e.g. Sarah Connor"
                      value={contactForm.name}
                      onChange={e => setContactForm({ ...contactForm, name: e.target.value })}
                      required
                      style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 12.5, background: 'transparent', height: 38, width: '100%', boxSizing: 'border-box' }}
                    />
                  </div>

                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
                    <label style={{ fontSize: 11.5, fontWeight: 600, color: '#334155' }}>Work Email *</label>
                    <input
                      type="email"
                      placeholder="analyst@enterprise.com"
                      value={contactForm.email}
                      onChange={e => setContactForm({ ...contactForm, email: e.target.value })}
                      required
                      style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 12.5, background: 'transparent', height: 38, width: '100%', boxSizing: 'border-box' }}
                    />
                  </div>
                </div>

                {/* 2-Column Row for Category & Urgency */}
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10, width: '100%', boxSizing: 'border-box' }}>
                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
                    <label style={{ fontSize: 11.5, fontWeight: 600, color: '#334155' }}>Inquiry Category</label>
                    <select
                      value={contactForm.inquiryType}
                      onChange={e => setContactForm({ ...contactForm, inquiryType: e.target.value })}
                      style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 12.5, background: 'transparent', height: 38, width: '100%', boxSizing: 'border-box' }}
                    >
                      <option value="Technical Support">Technical Support & Integration</option>
                      <option value="Security Escalation">Critical Vulnerability Escalation</option>
                      <option value="SLA Inquiry">SLA Policy / Reconfiguration</option>
                      <option value="Feature Request">Platform Feature Request</option>
                    </select>
                  </div>

                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
                    <label style={{ fontSize: 11.5, fontWeight: 600, color: '#334155' }}>Urgency Level</label>
                    <select
                      value={contactForm.priority}
                      onChange={e => setContactForm({ ...contactForm, priority: e.target.value })}
                      style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 12.5, background: 'transparent', height: 38, width: '100%', boxSizing: 'border-box' }}
                    >
                      <option value="Low">Low (General Inquiry)</option>
                      <option value="Medium">Medium (Business Hours)</option>
                      <option value="High">High (Immediate Review)</option>
                      <option value="Emergency">Emergency (Active Incident)</option>
                    </select>
                  </div>
                </div>

                {/* Details Message Box */}
                <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 4, width: '100%', boxSizing: 'border-box' }}>
                  <label style={{ fontSize: 11.5, fontWeight: 600, color: '#334155' }}>Message / Incident Details *</label>
                  <textarea
                    rows={3}
                    placeholder="Describe the issue, scanner anomaly, or finding ID requiring support..."
                    value={contactForm.message}
                    onChange={e => setContactForm({ ...contactForm, message: e.target.value })}
                    required
                    style={{ padding: '7px 10px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 12.5, background: 'transparent', width: '100%', boxSizing: 'border-box', resize: 'vertical' }}
                  />
                </div>

                {/* Secure Compliance disclaimer box at the bottom */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', borderRadius: '8px', border: '1px dashed #EDE9FE', background: '#FAF9FF' }}>
                  <Shield size={13} color="#7C3AED" style={{ flexShrink: 0 }} />
                  <span style={{ fontSize: '11px', color: '#6D28D9', fontWeight: 500 }}>
                    Secure TLS 1.3 encryption. INC ticket will generate on the audit ledger.
                  </span>
                </div>

                {/* Submit Action */}
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 2 }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={submittingContact}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      padding: '8px 20px',
                      height: 38,
                      borderRadius: '8px',
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: 'none',
                      background: 'linear-gradient(135deg, #7C3AED 0%, #4F46E5 100%)',
                      color: '#FFFFFF',
                      boxShadow: '0 4px 12px rgba(124, 58, 237, 0.25)',
                    }}
                  >
                    {submittingContact ? 'Submitting…' : 'Submit Ticket'}
                    <ArrowRight size={14} />
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
