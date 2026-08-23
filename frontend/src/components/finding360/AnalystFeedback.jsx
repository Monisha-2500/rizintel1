import React, { useState } from 'react';
import { useFeedback } from '../../hooks/useFeedback';
import { Check, ShieldAlert, ArrowDown, HelpCircle, EyeOff, Loader2 } from 'lucide-react';

export default function AnalystFeedback({ findingId }) {
  const { history, submit, submitting } = useFeedback(findingId);
  const [decision, setDecision] = useState(null);
  const [reason, setReason]     = useState('');
  const [showModal, setShowModal] = useState(false);

  const handleActionClick = (type) => {
    setDecision(type);
    if (type === 'DOWNGRADE' || type === 'FALSE_POSITIVE') {
      setReason('');
      setShowModal(true);
    } else {
      submit(type, '');
    }
  };

  const handleModalSubmit = () => {
    if (!reason.trim()) return;
    submit(decision, reason);
    setShowModal(false);
  };

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Analyst Decision & Human-in-the-Loop</div>
          <div className="card-subtitle">Record decision for model validation & governance</div>
        </div>
      </div>
      <div className="card-body">
        <div className="feedback-actions">
          <button
            className="btn btn-success btn-sm"
            id="btn-accept-priority"
            disabled={submitting}
            onClick={() => handleActionClick('ACCEPT_PRIORITY')}
          >
            <Check size={13} /> Accept Priority
          </button>

          <button
            className="btn btn-outline btn-sm"
            id="btn-escalate"
            disabled={submitting}
            onClick={() => handleActionClick('ESCALATE')}
            style={{ color: 'var(--risk-high)', borderColor: 'var(--risk-high-bdr)' }}
          >
            <ShieldAlert size={13} /> Escalate
          </button>

          <button
            className="btn btn-outline btn-sm"
            id="btn-downgrade"
            disabled={submitting}
            onClick={() => handleActionClick('DOWNGRADE')}
            style={{ color: 'var(--risk-medium)', borderColor: 'var(--risk-medium-bdr)' }}
          >
            <ArrowDown size={13} /> Downgrade
          </button>

          <button
            className="btn btn-outline btn-sm"
            id="btn-mark-review"
            disabled={submitting}
            onClick={() => handleActionClick('MARK_FOR_REVIEW')}
          >
            <HelpCircle size={13} /> Needs Review
          </button>

          <button
            className="btn btn-danger btn-sm"
            id="btn-false-positive"
            disabled={submitting}
            onClick={() => handleActionClick('FALSE_POSITIVE')}
          >
            <EyeOff size={13} /> False Positive
          </button>
        </div>

        {submitting && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, marginBottom: 12, color: 'var(--text-muted)' }}>
            <Loader2 size={12} className="pulse" />
            Recording analyst decision…
          </div>
        )}

        <div className="feedback-note">
          <strong>Notice:</strong> Analyst decisions are stored separately for governance and audit trails.
          M8 does not alter the upstream risk score.
        </div>

        {history && history.length > 0 && (
          <div style={{ marginTop: 'var(--space-4)' }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.8px', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
              Feedback Audit Trail ({history.length})
            </div>
            <div className="feedback-history">
              {history.map((entry, idx) => (
                <div key={idx} className="feedback-entry">
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="decision">
                      {(entry.analyst_decision ?? '').replace(/_/g, ' ')}
                    </span>
                    <span className="ts">
                      {new Date(entry.timestamp).toLocaleString()}
                    </span>
                  </div>
                  {entry.reason && <div className="reason">Reason: {entry.reason}</div>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <span className="modal-title">Justification Required</span>
              <button className="btn btn-ghost" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                Please provide a justification for marking this finding as{' '}
                <strong>{(decision ?? '').replace(/_/g, ' ')}</strong>.
              </p>
              <textarea
                placeholder="Describe your reasoning (e.g. compensating controls in place, staging environment only)..."
                value={reason}
                onChange={e => setReason(e.target.value)}
              />
            </div>
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setShowModal(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                onClick={handleModalSubmit}
                disabled={!reason.trim()}
              >
                Submit Decision
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
