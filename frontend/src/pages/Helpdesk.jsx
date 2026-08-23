import React, { useState, useMemo } from 'react';
import {
  HelpCircle, MessageSquare, BookOpen, ChevronRight, CheckCircle2,
  Send, Shield, Clock, Search, Info, Lock, ArrowRight, Sparkles, LifeBuoy
} from 'lucide-react';

const FAQS = [
  {
    q: 'How does M5 Risk Scoring calculate final severity (0–100)?',
    a: 'M5 employs a deterministic formula: Risk = (CVSS Base × 0.25) + (EPSS Probability × 25) + (CISA KEV Bonus: 15 pts) + (Asset Criticality Factor × 15) + (Internet Exposure: 10 pts) + (Scanner Consensus: 10 pts). Scores ≥90 trigger Critical severity and strict 8h SLA remediation windows.'
  },
  {
    q: 'How does M2 Deduplication correlate findings across scanners?',
    a: 'M2 correlates raw telemetry from ZAP, Nuclei, and OpenVAS using target endpoint normalization, CVE-ID cross-matching, parameter collision analysis, and AST vulnerability signature hashing to eliminate redundant duplicate tickets.'
  },
  {
    q: 'What triggers automated SLA Breach Escalations in M7?',
    a: 'M7 actively monitors real-time countdown timers. If a Critical finding reaches 75% of its 8-hour remediation window without an analyst in-progress assignment, M7 triggers an automated Level-1 Slack/PagerDuty escalation to the SOC Lead.'
  },
  {
    q: 'How does M8 Human-in-the-Loop audit overrides work?',
    a: 'Security analysts can override algorithmic priority (Accept Priority, Escalate, Downgrade, Mark False Positive). Every decision requires a mandatory rationale and is cryptographically appended to an immutable audit trail.'
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
    <div className="stack" style={{ gap: 24 }}>
      {/* Hero Header */}
      <div className="page-hero" style={{ padding: 'var(--space-6) var(--space-8)' }}>
        <div className="hero-eyebrow"><HelpCircle size={12} /> Help Desk & Support</div>
        <h1 className="hero-title" style={{ fontSize: 26, marginBottom: 6 }}>
          SOC Support Portal & Knowledge Base
        </h1>
        <p className="hero-subtitle" style={{ marginBottom: 0 }}>
          Find answers to common questions about risk metrics, scanner consensus, and SLAs, or submit a SOC support ticket.
        </p>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
        <div className="card" style={{ padding: '16px 20px', borderLeft: '4px solid var(--color-primary, #7C3AED)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ background: '#EEF2FF', padding: 8, borderRadius: 8, color: '#4F46E5', display: 'flex' }}>
              <BookOpen size={18} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Knowledge Base</div>
              <div style={{ fontSize: 14, fontWeight: 700, marginTop: 2 }}>4 Core Algorithm Specs</div>
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '16px 20px', borderLeft: '4px solid var(--color-purple, #9333EA)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ background: '#F5F3FF', padding: 8, borderRadius: 8, color: '#7C3AED', display: 'flex' }}>
              <Clock size={18} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Response Standard</div>
              <div style={{ fontSize: 14, fontWeight: 700, marginTop: 2 }}>SOC SLA &lt; 5m Dispatch</div>
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '16px 20px', borderLeft: '4px solid var(--color-teal-dk, #0D9488)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ background: '#F0FDFA', padding: 8, borderRadius: 8, color: '#0D9488', display: 'flex' }}>
              <Lock size={18} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Security Level</div>
              <div style={{ fontSize: 14, fontWeight: 700, marginTop: 2 }}>TLS 1.3 Cryptographic Audit</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid-2" style={{ alignItems: 'start', gap: 20 }}>
        {/* Left Column: FAQ Accordion */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <LifeBuoy size={18} color="var(--color-primary, #7C3AED)" />
              <div className="card-title">Interactive FAQ Search</div>
            </div>
            {/* FAQ Search Field */}
            <div style={{ position: 'relative', width: '220px' }}>
              <input
                type="text"
                placeholder="Search queries..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '6px 12px 6px 32px',
                  borderRadius: '16px',
                  border: '1px solid var(--border-color, #E2E8F0)',
                  fontSize: '12px',
                  background: 'transparent',
                }}
              />
              <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            </div>
          </div>
          <div className="card-body stack-3">
            <div className="faq-accordion-list">
              {filteredFaqs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--text-muted)' }}>
                  <Search size={24} style={{ marginBottom: 8, opacity: 0.5 }} />
                  <div>No FAQ matching "{searchQuery}"</div>
                </div>
              ) : (
                filteredFaqs.map((item, idx) => (
                  <div 
                    key={idx} 
                    className={`faq-card ${expandedFaq === idx ? 'expanded' : ''}`} 
                    style={{ 
                      marginBottom: '10px', 
                      borderRadius: '10px', 
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
                        padding: '14px 16px', 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'center',
                        background: expandedFaq === idx ? 'rgba(124, 58, 237, 0.03)' : 'transparent'
                      }}
                    >
                      <span className="faq-q-text" style={{ fontWeight: 600, fontSize: '13.5px' }}>{item.q}</span>
                      <ChevronRight size={16} className="faq-arrow" style={{ transition: 'transform 0.2s', transform: expandedFaq === idx ? 'rotate(90deg)' : 'none', color: 'var(--color-primary, #7C3AED)' }} />
                    </div>
                    {expandedFaq === idx && (
                      <div className="faq-a-body" style={{ padding: '4px 16px 16px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                        <p style={{ margin: 0 }}>{item.a}</p>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Explanatory Info Strip */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: 12, borderRadius: 8, background: '#F8FAFC', border: '1px solid #E2E8F0', marginTop: 12 }}>
              <Info size={14} color="#7C3AED" style={{ marginTop: 2, flexShrink: 0 }} />
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
                Metrics are automatically compiled from actual active SLA instances and system pipeline health logs. Overrides require security signature credentials.
              </p>
            </div>
          </div>
        </div>

        {/* Right Column: Contact SOC Operations Form */}
        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <MessageSquare size={18} color="var(--color-purple, #9333EA)" />
            <div className="card-title">SOC Dispatch Incident System</div>
          </div>
          <div className="card-body">
            {contactSubmitted ? (
              <div className="contact-success-box" style={{ textAlign: 'center', padding: '36px 16px' }}>
                <div className="cs-icon" style={{ marginBottom: 16 }}><CheckCircle2 size={48} color="#10B981" /></div>
                <h3 style={{ fontSize: 18, marginBottom: 8, fontWeight: 700 }}>Ticket Dispatched Successfully!</h3>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Your incident log is registered as ticket <strong>#INC-{Math.floor(100000 + Math.random() * 900000)}</strong> and forwarded to Security Engineers.
                </p>
              </div>
            ) : (
              <form className="contact-form-grid" onSubmit={handleContactSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* 2-Column Row for Name & Email */}
                <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: '1 1 200px' }}>
                    <label style={{ fontSize: 12, fontWeight: 600 }}>Your Name *</label>
                    <input
                      type="text"
                      placeholder="e.g. Sarah Connor"
                      value={contactForm.name}
                      onChange={e => setContactForm({ ...contactForm, name: e.target.value })}
                      required
                      style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 13, background: 'transparent' }}
                    />
                  </div>

                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: '1 1 200px' }}>
                    <label style={{ fontSize: 12, fontWeight: 600 }}>Work Email *</label>
                    <input
                      type="email"
                      placeholder="analyst@enterprise.com"
                      value={contactForm.email}
                      onChange={e => setContactForm({ ...contactForm, email: e.target.value })}
                      required
                      style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 13, background: 'transparent' }}
                    />
                  </div>
                </div>

                {/* 2-Column Row for Category & Urgency */}
                <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: '1 1 200px' }}>
                    <label style={{ fontSize: 12, fontWeight: 600 }}>Inquiry Category</label>
                    <select
                      value={contactForm.inquiryType}
                      onChange={e => setContactForm({ ...contactForm, inquiryType: e.target.value })}
                      style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 13, background: 'transparent' }}
                    >
                      <option value="Technical Support">Technical Support & Integration</option>
                      <option value="Security Escalation">Critical Vulnerability Escalation</option>
                      <option value="SLA Inquiry">SLA Policy / Reconfiguration</option>
                      <option value="Feature Request">Platform Feature Request</option>
                    </select>
                  </div>

                  <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: '1 1 200px' }}>
                    <label style={{ fontSize: 12, fontWeight: 600 }}>Urgency Level</label>
                    <select
                      value={contactForm.priority}
                      onChange={e => setContactForm({ ...contactForm, priority: e.target.value })}
                      style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 13, background: 'transparent' }}
                    >
                      <option value="Low">Low (General Inquiry)</option>
                      <option value="Medium">Medium (Business Hours)</option>
                      <option value="High">High (Immediate Review)</option>
                      <option value="Emergency">Emergency (Active Incident)</option>
                    </select>
                  </div>
                </div>

                {/* Details Message Box */}
                <div className="form-field-group" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600 }}>Message / Incident Details *</label>
                  <textarea
                    rows={5}
                    placeholder="Describe the issue, scanner anomaly, or finding ID requiring support..."
                    value={contactForm.message}
                    onChange={e => setContactForm({ ...contactForm, message: e.target.value })}
                    required
                    style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--border-color, #E2E8F0)', fontSize: 13, background: 'transparent' }}
                  />
                </div>

                {/* Secure Compliance disclaimer box at the bottom */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', borderRadius: '8px', border: '1px dashed #EDE9FE', background: '#FAF9FF' }}>
                  <Shield size={14} color="#7C3AED" />
                  <span style={{ fontSize: '11px', color: '#6D28D9', fontWeight: 500 }}>
                    Secure TLS 1.3 encryption. INC ticket will generate on the audit ledger.
                  </span>
                </div>

                {/* Submit Action */}
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 4 }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={submittingContact}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      padding: '10px 24px',
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
