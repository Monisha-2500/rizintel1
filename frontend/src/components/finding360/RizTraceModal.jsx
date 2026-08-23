import React, { useState, useMemo } from 'react';
import {
  GitCommit, X, ChevronDown, ChevronUp, CheckCircle2, AlertCircle, Clock,
  Layers, Search, Zap, Target, ShieldAlert, FileText, UserCheck, Copy, Check,
  Network, ArrowRight, Shield, Flame, Globe
} from 'lucide-react';
import { buildDecisionProvenanceChain } from '../../utils/provenanceGraph';

const STAGE_ICONS = {
  1: Search,      // Scanner Ingestion
  2: Zap,         // Deduplication & Consensus
  3: CheckCircle2,// Noise Filter & Confidence
  4: Target,      // Threat Intel & Asset Context
  5: ShieldAlert, // Dynamic Risk Score
  6: FileText,    // Explainability Rationale
  7: UserCheck,   // SLA & Remediation
  8: GitCommit    // Analyst Decision
};

export default function RizTraceModal({ finding, feedbackHistory = [], onClose }) {
  const [traversalMode, setTraversalMode] = useState('BFS'); // 'BFS' | 'DFS'
  const [expandedNodes, setExpandedNodes] = useState(() => {
    // All stages collapsed by default
    return {};
  });
  const [copied, setCopied] = useState(false);

  // Build the graph using BFS/DFS logic from provenanceGraph.js
  const provenanceData = useMemo(() => {
    return buildDecisionProvenanceChain(finding, feedbackHistory);
  }, [finding, feedbackHistory]);

  const { nodes, edges, bfsOrder, dfsOrder } = provenanceData;
  const activeOrder = traversalMode === 'BFS' ? bfsOrder : dfsOrder;

  const toggleNode = (nodeId) => {
    setExpandedNodes(prev => ({
      ...prev,
      [nodeId]: !prev[nodeId]
    }));
  };

  const handleExpandAll = () => {
    const all = {};
    activeOrder.forEach(id => { all[id] = true; });
    setExpandedNodes(all);
  };

  const handleCollapseAll = () => {
    setExpandedNodes({});
  };

  const handleCopyTrace = () => {
    if (!finding) return;
    const summaryLines = activeOrder.map(id => {
      const node = nodes.get(id);
      if (!node) return '';
      return `[Stage ${node.stageIndex}: ${node.title}] (${node.status}) - ${node.summary}`;
    }).filter(Boolean);

    const traceText = `RizTrace Decision Provenance for ${finding.finding_id} (${finding.vulnerability_name})\nRisk Score: ${finding.risk_score} (${finding.risk_level})\nTraversal Mode: ${traversalMode}\n\n` + summaryLines.join('\n');
    
    navigator.clipboard.writeText(traceText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!finding) return null;

  return (
    <div className="riztrace-modal-overlay" onClick={onClose}>
      <div className="riztrace-modal-card" onClick={e => e.stopPropagation()}>
        {/* ── Modal Header ── */}
        <div className="riztrace-modal-header">
          <div className="riztrace-header-title-row">
            <div className="riztrace-brand-icon">
              <GitCommit size={20} />
            </div>
            <div>
              <div className="riztrace-modal-title">
                RizTrace – Decision Provenance
              </div>
              <div className="riztrace-modal-subtitle">
                End-to-end decision lineage from scanner ingestion to analyst governance
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
            <button className="riztrace-close-btn" onClick={onClose} title="Close RizTrace">
              <X size={18} />
            </button>
          </div>
        </div>

        {/* ── Toolbar & Traversal Controls ── */}
        <div className="riztrace-toolbar">
          <div className="riztrace-mode-toggle">
            <span className="riztrace-mode-label">Traversal Mode:</span>
            <div className="riztrace-mode-btns">
              <button
                className={`riztrace-mode-btn ${traversalMode === 'BFS' ? 'active' : ''}`}
                onClick={() => setTraversalMode('BFS')}
                title="Breadth-First Search: Sequential Ingestion Order"
              >
                <Layers size={13} />
                <span>BFS (Ingestion Order)</span>
              </button>
              <button
                className={`riztrace-mode-btn ${traversalMode === 'DFS' ? 'active' : ''}`}
                onClick={() => setTraversalMode('DFS')}
                title="Depth-First Search: Deep Dependency Chain"
              >
                <Network size={13} />
                <span>DFS (Dependency Order)</span>
              </button>
            </div>
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

        {/* ── Visual Provenance Lineage Pipeline ── */}
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
                  title={`Step ${idx + 1}: ${node.title}`}
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

        {/* ── Main Graph Nodes Container ── */}
        <div className="riztrace-modal-body">
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
                  {/* Node Card */}
                  <div className={`riztrace-node-card ${node.status.toLowerCase()}`}>
                    {/* Header */}
                    <div
                      className="riztrace-node-header"
                      onClick={() => toggleNode(nodeId)}
                    >
                      <div className="riztrace-node-left">
                        <div className="riztrace-step-number">
                          #{node.stageIndex}
                        </div>
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
                        <button className="riztrace-expand-toggle">
                          {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                        </button>
                      </div>
                    </div>

                    {/* Expanded Detail Panel */}
                    {isExpanded && (
                      <div className="riztrace-node-details fade-in">
                        {node.status === 'NOT_AVAILABLE' ? (
                          <div className="riztrace-not-available-box">
                            <AlertCircle size={15} color="var(--risk-medium)" />
                            <span>Data Not Available — This stage information was not present in the current finding payload.</span>
                          </div>
                        ) : node.status === 'PENDING' ? (
                          <div className="riztrace-pending-box">
                            <Clock size={15} color="var(--color-primary)" />
                            <span>Pending Analyst Review — No human override decision recorded. The M5 dynamic risk score remains active.</span>
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
                                        <span key={i} className="chip chip-purple">{typeof item === 'object' ? item.scanner || item.finding_id : item}</span>
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
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Connecting Relation Rail (if not last step) */}
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
        </div>

        {/* ── Modal Footer ── */}
        <div className="riztrace-modal-footer">
          <div className="riztrace-footer-info">
            <strong>RizTrace Governance Notice:</strong> Proving complete decision chain from original ingestion alerts to analyst decision. M5 Risk Score is preserved without recalculation.
          </div>
          <button className="btn btn-secondary" onClick={onClose}>
            Close Decision Provenance
          </button>
        </div>
      </div>
    </div>
  );
}
