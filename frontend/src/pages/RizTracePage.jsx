import React, { useState, useMemo, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import {
  GitCommit, ArrowLeft, ChevronDown, ChevronUp, CheckCircle2, AlertCircle, Clock,
  Layers, Search, Zap, Target, ShieldAlert, FileText, UserCheck, Copy, Check,
  Network, ArrowRight, Shield, AlertTriangle
} from 'lucide-react';
import { getFindingById, getFeedbackForFinding } from '../services/findingsService';
import { buildDecisionProvenanceChain } from '../utils/provenanceGraph';
import './RizTracePage.css';

const STAGE_ICONS = {
  1: Search,
  2: Zap,
  3: CheckCircle2,
  4: Target,
  5: ShieldAlert,
  6: FileText,
  7: UserCheck,
  8: GitCommit
};

export default function RizTracePage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const scanRunId = searchParams.get('scan_run_id');
  const orgId = searchParams.get('org_id');
  const focusStage = searchParams.get('stage') || searchParams.get('focus');

  const [finding, setFinding] = useState(null);
  const [feedbackHistory, setFeedbackHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  const [traversalMode, setTraversalMode] = useState('BFS');
  const [expandedNodes, setExpandedNodes] = useState(() => {
    if (focusStage === 'stage_explanation' || focusStage === 'explainability') {
      return { stage_explanation: true };
    }
    return {};
  });
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (focusStage === 'stage_explanation' || focusStage === 'explainability') {
      setExpandedNodes(prev => ({ ...prev, stage_explanation: true }));
    }
  }, [focusStage]);

  useEffect(() => {
    setLoading(true);
    getFindingById(id, scanRunId, orgId).then(data => {
      setFinding(data);
      setLoading(false);
      if (data) {
        const history = getFeedbackForFinding(data.finding_id);
        setFeedbackHistory(history);
      }
    }).catch(err => {
      console.error('Failed to load finding for RizTrace:', err);
      setFinding(null);
      setLoading(false);
    });
  }, [id, scanRunId, orgId]);

  const provenanceData = useMemo(() => {
    if (!finding) return { nodes: new Map(), edges: new Map(), bfsOrder: [], dfsOrder: [] };
    return buildDecisionProvenanceChain(finding, feedbackHistory);
  }, [finding, feedbackHistory]);

  const { nodes, edges, bfsOrder, dfsOrder } = provenanceData;

  // BFS = strict ingestion order (stages 1->2->3->4->5->6->7->8)
  // DFS = risk-core-first: pivot from Risk Score (#5), go back through its dependencies,
  //       then forward through explainability and governance
  const dfsDisplayOrder = useMemo(() => {
    if (bfsOrder.length !== 8) return dfsOrder;
    return [
      bfsOrder[4], // stage_risk_score (#5) - pivot
      bfsOrder[3], // stage_threat_asset (#4) - risk input
      bfsOrder[2], // stage_confidence (#3) - risk input
      bfsOrder[1], // stage_deduplication (#2) - root
      bfsOrder[0], // stage_scanner (#1) - origin
      bfsOrder[5], // stage_explanation (#6) - forward
      bfsOrder[6], // stage_sla_remediation (#7)
      bfsOrder[7], // stage_analyst_decision (#8)
    ];
  }, [bfsOrder, dfsOrder]);

  const activeOrder = traversalMode === 'BFS' ? bfsOrder : dfsDisplayOrder;

  const toggleNode = (nodeId) => {
    setExpandedNodes(prev => ({
      ...prev,
      [nodeId]: !prev[nodeId]
    }));
  };

  const handleExpandAll = () => {
    const all = {};
    activeOrder.forEach(nid => { all[nid] = true; });
    setExpandedNodes(all);
  };

  const handleCollapseAll = () => {
    setExpandedNodes({});
  };

  const handleSetTraversal = (mode) => {
    setTraversalMode(mode);
    setExpandedNodes({});
  };

  const handleCopyTrace = () => {
    if (!finding) return;
    const summaryLines = activeOrder.map(nid => {
      const node = nodes.get(nid);
      if (!node) return '';
      return `[Stage ${node.stageIndex}: ${node.title}] (${node.status}) - ${node.summary}`;
    }).filter(Boolean);

    const traceText = `RizTrace Decision Provenance for ${finding.finding_id} (${finding.vulnerability_name})\nRisk Score: ${finding.risk_score} (${finding.risk_level})\nTraversal Mode: ${traversalMode}\n\n` + summaryLines.join('\n');

    navigator.clipboard.writeText(traceText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="riztrace-page-loading">
        <div className="riztrace-loading-spinner" />
        <p>Loading Decision Provenance...</p>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="riztrace-page-error">
        <AlertTriangle size={36} color="#EF4444" />
        <h3>Finding {id} not found</h3>
        <button className="btn btn-primary" onClick={() => navigate('/findings')} style={{ marginTop: 16 }}>
          Back to Findings Queue
        </button>
      </div>
    );
  }

  return (
    <div className="riztrace-page">
      {/* Page Header */}
      <div className="riztrace-page-header">
        <div className="riztrace-page-header-left">
          <button
            className="riztrace-back-btn"
            onClick={() => navigate(`/findings/${id}`)}
          >
            <ArrowLeft size={16} />
            <span>Back to Finding</span>
          </button>
          <div className="riztrace-page-brand">
            <div className="riztrace-brand-icon">
              <GitCommit size={20} />
            </div>
            <div>
              <div className="riztrace-modal-title">RizTrace - Decision Provenance</div>
              <div className="riztrace-modal-subtitle">
                End-to-end decision lineage from scanner ingestion to analyst governance
              </div>
            </div>
          </div>
        </div>

        <div className="riztrace-header-right">
          <div className="riztrace-meta-pills">
            <span className="riztrace-pill mono">{finding.finding_id}</span>
            {finding.cve_id && <span className="riztrace-pill cve">{finding.cve_id}</span>}
            <span className={`riztrace-pill score ${finding.risk_level?.toLowerCase() || 'critical'}`}>
              Risk Score {finding.risk_score}
            </span>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="riztrace-toolbar riztrace-page-toolbar">
        <div className="riztrace-mode-toggle">
          <span className="riztrace-mode-label">Traversal Mode:</span>
          <div className="riztrace-mode-btns">
            <button
              className={`riztrace-mode-btn ${traversalMode === 'BFS' ? 'active' : ''}`}
              onClick={() => handleSetTraversal('BFS')}
              title="Breadth-First: Sequential ingestion order 1->2->3->4->5->6->7->8"
            >
              <Layers size={13} />
              <span>BFS (Ingestion Order)</span>
            </button>
            <button
              className={`riztrace-mode-btn ${traversalMode === 'DFS' ? 'active' : ''}`}
              onClick={() => handleSetTraversal('DFS')}
              title="Depth-First: Pivot at Risk Score, trace back to origins, then forward"
            >
              <Network size={13} />
              <span>DFS (Risk-Core First)</span>
            </button>
          </div>
          {traversalMode === 'DFS' && (
            <span className="riztrace-traversal-hint">
              Pivot: Risk Score #5 - tracing back to origins then forward through governance
            </span>
          )}
        </div>

        <div className="riztrace-toolbar-actions">
          <button className="riztrace-tool-btn" onClick={handleExpandAll}>
            <ChevronDown size={13} /> Expand All
          </button>
          <button className="riztrace-tool-btn" onClick={handleCollapseAll}>
            <ChevronUp size={13} /> Collapse All
          </button>
          <button className="riztrace-tool-btn primary" onClick={handleCopyTrace}>
            {copied ? <Check size={13} /> : <Copy size={13} />}
            <span>{copied ? 'Copied!' : 'Copy Trace Summary'}</span>
          </button>
        </div>
      </div>

      {/* Pipeline Nav Rail */}
      <div className="riztrace-pipeline-summary">
        {activeOrder.map((nodeId, idx) => {
          const node = nodes.get(nodeId);
          if (!node) return null;
          const Icon = STAGE_ICONS[node.stageIndex] || Shield;
          const isOpen = !!expandedNodes[nodeId];

          return (
            <React.Fragment key={nodeId}>
              <button
                className={`riztrace-step-pill ${node.status.toLowerCase()} ${isOpen ? 'open' : ''}`}
                onClick={() => toggleNode(nodeId)}
                title={`Stage ${node.stageIndex}: ${node.title}`}
              >
                <Icon size={12} />
                <span>{node.stageIndex}. {node.title}</span>
              </button>
              {idx < activeOrder.length - 1 && (
                <ArrowRight size={12} className="riztrace-pipeline-arrow" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Stage Cards */}
      <div className="riztrace-page-body">
        <div className="riztrace-graph-nodes-list">
          {activeOrder.map((nodeId, idx) => {
            const node = nodes.get(nodeId);
            if (!node) return null;

            const Icon = STAGE_ICONS[node.stageIndex] || Shield;
            const isExpanded = !!expandedNodes[nodeId];
            const outgoingEdges = edges.get(nodeId) || [];
            const relation = outgoingEdges[0]?.relation;

            return (
              <div key={nodeId} className="riztrace-node-wrapper">
                <div className={`riztrace-node-card ${node.status.toLowerCase()}`}>
                  <div
                    className="riztrace-node-header"
                    onClick={() => toggleNode(nodeId)}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className="riztrace-node-left">
                      <div className="riztrace-step-number">#{node.stageIndex}</div>
                      <div className="riztrace-node-icon-box">
                        <Icon size={16} />
                      </div>
                      <div className="riztrace-node-title-group">
                        <div className="riztrace-node-title-row">
                          <span className="riztrace-node-title">{node.title}</span>
                          <span className="riztrace-cat-chip">{node.category}</span>
                        </div>
                        <div className="riztrace-node-summary">{node.summary}</div>
                      </div>
                    </div>

                    <div className="riztrace-node-right">
                      <span className={`riztrace-status-badge ${node.status.toLowerCase()}`}>
                        {node.status === 'AVAILABLE' ? 'AVAILABLE' : node.status === 'PENDING' ? 'PENDING REVIEW' : 'NOT AVAILABLE'}
                      </span>
                      <button
                        className="riztrace-expand-toggle"
                        onClick={(e) => { e.stopPropagation(); toggleNode(nodeId); }}
                      >
                        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </button>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="riztrace-node-details fade-in">
                      {node.status === 'NOT_AVAILABLE' ? (
                        <div className="riztrace-not-available-box">
                          <AlertCircle size={15} color="var(--risk-medium)" />
                          <span>Data Not Available - This stage information was not present in the current finding payload.</span>
                        </div>
                      ) : node.status === 'PENDING' ? (
                        <div className="riztrace-pending-box">
                          <Clock size={15} color="var(--color-primary)" />
                          <span>Pending Analyst Review - No human override decision recorded. The M5 dynamic risk score remains active.</span>
                        </div>
                      ) : (
                        <div className="riztrace-details-grid">
                          {Object.entries(node.details).map(([key, val]) => {
                            if (val == null || val === '') return null;
                            const formattedKey = key.replace(/_/g, ' ').toUpperCase();

                            if (typeof val === 'object' && !Array.isArray(val)) {
                              return (
                                <div key={key} className="riztrace-detail-item full-width">
                                  <span className="riztrace-detail-label">{formattedKey}</span>
                                  <pre className="riztrace-json-code">{JSON.stringify(val, null, 2)}</pre>
                                </div>
                              );
                            }

                            if (Array.isArray(val)) {
                              return (
                                <div key={key} className="riztrace-detail-item full-width">
                                  <span className="riztrace-detail-label">{formattedKey}</span>
                                  <div className="riztrace-chips-group">
                                    {val.length > 0 ? val.map((item, i) => (
                                      <span key={i} className="chip chip-purple">
                                        {typeof item === 'object' ? (item.finding_id || item.scanner) : item}
                                      </span>
                                    )) : <span className="text-muted">None</span>}
                                  </div>
                                </div>
                              );
                            }

                            return (
                              <div key={key} className="riztrace-detail-item">
                                <span className="riztrace-detail-label">{formattedKey}</span>
                                <span className="riztrace-detail-value">{String(val)}</span>
                              </div>
                            );
                          })}
                          {nodeId === 'stage_explanation' && (
                            <div className="riztrace-detail-item full-width" style={{ marginTop: '10px' }}>
                              <button
                                className="riztrace-tool-btn primary"
                                onClick={() => {
                                  const query = new URLSearchParams();
                                  query.set('tab', 'explainability');
                                  if (scanRunId) query.set('scan_run_id', scanRunId);
                                  if (orgId) query.set('org_id', orgId);
                                  navigate(`/findings/${finding.finding_id}?${query.toString()}`);
                                }}
                                aria-label="Open in Finding360 Explainability Tab"
                                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                              >
                                <FileText size={14} />
                                <span>Open in Finding360 Explainability Tab →</span>
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {idx < activeOrder.length - 1 && (
                  <div className="riztrace-relation-rail">
                    <div className="riztrace-rail-line" />
                    {relation && (
                      <span className="riztrace-relation-tag">
                        {relation.replace(/_/g, ' ')}
                      </span>
                    )}
                    <div className="riztrace-rail-line" />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="riztrace-page-footer-notice">
          <strong>RizTrace Governance Notice:</strong> Proving complete decision chain from original ingestion alerts to analyst decision. M5 Risk Score is preserved without recalculation.
        </div>
      </div>
    </div>
  );
}
