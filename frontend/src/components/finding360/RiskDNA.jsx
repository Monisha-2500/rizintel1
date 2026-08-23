import React from 'react';
import ReactFlow, { Background, Handle, Position } from 'reactflow';
import 'reactflow/dist/style.css';
import { buildRiskDNANodes } from '../../utils/provenanceGraph';

const RiskDNANode = ({ data }) => {
  return (
    <div className={`rf-node-card ${data.nodeClass || ''}`} id={`node-${data.label.toLowerCase().replace(/\s+/g, '-')}`}>
      {data.nodeClass !== 'center-node' && (
        <Handle type="source" position={Position.Right} style={{ background: 'currentColor' }} />
      )}
      {data.nodeClass === 'center-node' && (
        <Handle type="target" position={Position.Left} style={{ background: 'currentColor' }} />
      )}

      <div className="node-category">{data.category}</div>
      <div className="node-label">{data.label}</div>
      <div className="node-value">{data.value}</div>
    </div>
  );
};

const nodeTypes = {
  riskDNANode: RiskDNANode,
};

export default function RiskDNA({ finding }) {
  const { rfNodes, rfEdges } = buildRiskDNANodes(finding);

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Risk DNA Graph</div>
          <div className="card-subtitle">Visual decision provenance graph — score drivers and context</div>
        </div>
      </div>
      <div className="card-body">
        <div className="risk-dna-container">
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.12 }}
            zoomOnScroll={false}
            zoomOnDoubleClick={false}
            zoomOnPinch={false}
            panOnScroll={false}
            panOnDrag={true}
            preventScrolling={true}
          >
            <Background color="#CBD5E1" gap={16} size={1} />
          </ReactFlow>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 'var(--space-3)' }}>
          Risk DNA visualizes CVSS, asset criticality, exposure, consensus, and SLA factors contributing to the score.
          The risk score is visualized directly as supplied by the engine.
        </div>
      </div>
    </div>
  );
}
