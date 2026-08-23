import React from 'react';
import { useNavigate } from 'react-router-dom';
import { RiskPill, SLABadge, WorkflowBadge } from '../common/Badges';

export default function SLATable({ items }) {
  const navigate = useNavigate();

  if (!items || items.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 'var(--space-6)' }}>
        <div className="empty-state-icon">✅</div>
        <h3>No findings in this SLA status</h3>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Score</th>
            <th>Vulnerability</th>
            <th>Asset</th>
            <th>Assigned Owner</th>
            <th>Ticket ID</th>
            <th>SLA Deadline</th>
            <th>SLA Status</th>
            <th>Escalation</th>
          </tr>
        </thead>
        <tbody>
          {items.map(item => (
            <tr
              key={item.finding_id}
              className="clickable"
              onClick={() => navigate(`/findings/${item.finding_id}`)}
            >
              <td><RiskPill score={item.risk_score} level={item.risk_level} /></td>
              <td>
                <div style={{ fontWeight: 700 }}>{item.vulnerability_name}</div>
                <div className="text-muted text-small">{item.finding_id}</div>
              </td>
              <td>
                <div style={{ fontWeight: 600 }}>{item.asset_display}</div>
                <div className="text-muted text-small">{item.asset_id}</div>
              </td>
              <td style={{ fontWeight: 600 }}>{item.owner}</td>
              <td className="text-mono">{item.ticket_id}</td>
              <td style={{ fontSize: 12 }}>
                {item.sla_due_at ? new Date(item.sla_due_at).toLocaleString() : '—'}
              </td>
              <td><SLABadge status={item.sla_status} /></td>
              <td>
                <span className={`chip ${item.escalation_level > 0 ? 'chip-critical' : 'chip-gray'}`}>
                  Lvl {item.escalation_level}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
